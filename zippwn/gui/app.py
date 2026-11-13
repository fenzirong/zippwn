"""ZipPwn 图形界面（PySide6）。

架构：GUI 只做壳，全部破解逻辑在 zippwn.dll（C++）。
Python 通过 ctypes 调用 C ABI，进度回调 + 原子取消标志跨语言传递。

    ┌──────────────────────────┐   ctypes    ┌─────────────────────┐
    │ PySide6 (app.py)         │ ──────────► │ zippwn.dll (C++20)  │
    │  · 参数收集              │ ◄────────── │  · ZIP 解析          │
    │  · 进度渲染              │  progress   │  · 多线程催破        │
    │  · 结果展示              │  callback   │  · DEFLATE 复核      │
    └──────────────────────────┘             └─────────────────────┘

运行： python -m zippwn.gui.app   或   run_gui.bat
"""

from __future__ import annotations

import ctypes
import json
import os
import queue
import sys
import threading
import time

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout,
    QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar,
    QPushButton, QSpinBox, QSplitter, QTabWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

HERE = os.path.dirname(os.path.abspath(__file__))


def _search_dirs() -> list[str]:
    """按优先级返回资源搜索目录，兼容源码运行与 PyInstaller 冻结运行。"""
    dirs: list[str] = []
    if getattr(sys, "frozen", False):
        # onefile: 解包到 _MEIPASS；onedir: 与 exe 同目录
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            dirs.append(meipass)
        dirs.append(os.path.dirname(os.path.abspath(sys.executable)))
    root = os.path.dirname(os.path.dirname(HERE))
    dirs += [
        os.path.join(root, "build"),
        root,
        HERE,
        os.getcwd(),
    ]
    seen: set[str] = set()
    out: list[str] = []
    for d in dirs:
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _find_file(name: str) -> str | None:
    for d in _search_dirs():
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


_found_dll = _find_file("zippwn.dll")
DLL_CANDIDATES = [_found_dll] if _found_dll else ["zippwn.dll"]

PROGRESS_CB = ctypes.CFUNCTYPE(None, ctypes.c_ulonglong, ctypes.c_ulonglong,
                               ctypes.c_double, ctypes.c_void_p)


# ---------------------------------------------------------------- DLL 绑定
class Core:
    def __init__(self) -> None:
        self.lib = None
        self.error = ""
        for cand in DLL_CANDIDATES:
            if not os.path.exists(cand) and cand != "zippwn.dll":
                continue
            try:
                lib = ctypes.CDLL(cand)
            except OSError as e:
                self.error = f"{cand}: {e}"
                continue
            try:
                lib.zpwn_version.restype = ctypes.c_char_p
                lib.zpwn_info.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
                lib.zpwn_report.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
                lib.zpwn_pairs.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
                lib.zpwn_crack.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                           ctypes.c_size_t, PROGRESS_CB, ctypes.c_void_p,
                                           ctypes.POINTER(ctypes.c_int)]
                lib.zpwn_gpu_info.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                lib.zpwn_gpu_crack.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                               ctypes.c_char_p, ctypes.c_size_t]
                lib.zpwn_export_hash.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
                lib.zpwn_selftest.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                self.lib = lib
                self.path = cand
                break
            except AttributeError as e:
                self.error = f"导出符号缺失: {e}"
        if self.lib is None and not self.error:
            self.error = "未找到 build\\zippwn.dll，请先运行 tools\\build.ps1"

    @property
    def ok(self) -> bool:
        return self.lib is not None

    def version(self) -> str:
        return self.lib.zpwn_version().decode() if self.lib else "?"

    def _call_str(self, fn, *args, cap=1 << 20) -> str:
        buf = ctypes.create_string_buffer(cap)
        fn(*args, buf, cap)
        return buf.value.decode("utf-8", "replace")

    def info(self, path: str) -> dict:
        try:
            return json.loads(self._call_str(self.lib.zpwn_info, path.encode()))
        except Exception:
            return {"ok": False}

    def report(self, path: str) -> str:
        return self._call_str(self.lib.zpwn_report, path.encode(), cap=1 << 18)

    def pairs(self, path: str) -> list:
        try:
            return json.loads(self._call_str(self.lib.zpwn_pairs, path.encode()))
        except Exception:
            return []

    def export_hash(self, path: str) -> str:
        return self._call_str(self.lib.zpwn_export_hash, path.encode(), cap=1 << 22)

    def gpu_info(self) -> dict:
        try:
            return json.loads(self._call_str(self.lib.zpwn_gpu_info, cap=1 << 16))
        except Exception:
            return {"available": False}

    def selftest(self) -> str:
        return self._call_str(self.lib.zpwn_selftest, cap=1 << 16)


# ---------------------------------------------------------------- 破解工作线程
class CrackWorker(threading.Thread):
    def __init__(self, core: Core, path: str, cfg: str, gpu: bool, out: queue.Queue):
        super().__init__(daemon=True)
        self.core, self.path, self.cfg, self.gpu = core, path, cfg, gpu
        self.out = out
        self.cancel = ctypes.c_int(0)
        self._cb = PROGRESS_CB(self._on_progress)

    def _on_progress(self, tried, total, speed, _user):
        self.out.put(("progress", (tried, total, speed)))

    def run(self) -> None:
        try:
            buf = ctypes.create_string_buffer(512)
            if self.gpu:
                rc = self.core.lib.zpwn_gpu_crack(self.path.encode(), self.cfg.encode(),
                                                  buf, 512)
                self.out.put(("done", (bool(rc) and rc > 1, buf.value.decode("utf-8", "replace"))))
                return
            rc = self.core.lib.zpwn_crack(self.path.encode(), self.cfg.encode(), buf, 512,
                                          self._cb, None, ctypes.byref(self.cancel))
            if rc > 0:
                self.out.put(("done", (True, buf.value.decode("utf-8", "replace"))))
            else:
                self.out.put(("done", (False, buf.value.decode("utf-8", "replace") or "未命中")))
        except Exception as e:  # noqa: BLE001
            self.out.put(("done", (False, f"内部错误: {e}")))

    def stop(self) -> None:
        self.cancel.value = 1


# ---------------------------------------------------------------- 主窗口
RULES = [
    ("none", True), ("lower", True), ("upper", True), ("capitalize", True),
    ("leet", True), ("reverse", False), ("dup", False), ("swapcase", False),
    ("append_digits", False), ("append_years", False), ("append_symbols", False),
    ("best64lite", False),
]
MASK_PRESETS = [
    ("6 位纯数字", "?d?d?d?d?d?d"),
    ("8 位纯数字", "?d?d?d?d?d?d?d?d"),
    ("4 位小写", "?l?l?l?l"),
    ("6 位小写", "?l?l?l?l?l?l"),
    ("8 位小写", "?l?l?l?l?l?l?l?l"),
    ("6 位小写+数字", "?l?l?l?l?d?d"),
    ("8 位小写+数字", "?l?l?l?l?d?d?d?d"),
    ("首字母大写+6 小写", "?u?l?l?l?l?l?l"),
    ("8 位全字符集", "?a?a?a?a?a?a?a?a"),
]


class MainWindow(QMainWindow):
    def __init__(self, core: Core) -> None:
        super().__init__()
        self.core = core
        self.worker: CrackWorker | None = None
        self.events: queue.Queue = queue.Queue()
        self.t0 = 0.0
        self.last_tried = 0
        self.archive: dict = {}

        self.setWindowTitle(f"ZipPwn {core.version() if core.ok else ''} — 压缩包口令恢复工作台")
        self.resize(1120, 760)
        self._build_ui()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._drain)
        self.timer.start(80)

        if not core.ok:
            self._log(f"[!] C++ 内核未加载: {core.error}")
            self._log("    请先运行:  pwsh -File tools\\build.ps1")
            self.btn_start.setEnabled(False)
        else:
            self._log(f"[+] 内核已加载: {core.path}  (version {core.version()})")

    # ---------------- UI 构建 ----------------
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(10)

        # --- 顶部：目标文件 ---
        top = QHBoxLayout()
        top.addWidget(QLabel("目标压缩包"))
        self.ed_path = QLineEdit()
        self.ed_path.setPlaceholderText("选择 .zip / .rar / .7z 文件…")
        self.ed_path.setReadOnly(True)
        top.addWidget(self.ed_path, 1)
        btn_browse = QPushButton("浏览…")
        btn_browse.clicked.connect(self._pick_file)
        top.addWidget(btn_browse)
        btn_self = QPushButton("内核自测")
        btn_self.clicked.connect(self._selftest)
        top.addWidget(btn_self)
        root.addLayout(top)

        # --- 中部：左配置 右输出 ---
        split = QSplitter(Qt.Horizontal)

        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)

        # 概览
        box_info = QGroupBox("容器概览")
        iv = QVBoxLayout(box_info)
        self.lb_info = QLabel("尚未选择文件")
        self.lb_info.setWordWrap(True)
        self.lb_info.setAlignment(Qt.AlignTop)
        iv.addWidget(self.lb_info)
        lv.addWidget(box_info)

        # 攻击配置
        self.tabs = QTabWidget()

        # -- 字典 --
        t_dict = QWidget()
        dv = QVBoxLayout(t_dict)
        dv.addWidget(QLabel("字典文件（可多选，按顺序处理）"))
        self.lst_dict = QListWidget()
        self.lst_dict.setMaximumHeight(110)
        dv.addWidget(self.lst_dict)
        dh = QHBoxLayout()
        b1 = QPushButton("添加…")
        b1.clicked.connect(self._add_dict)
        b2 = QPushButton("移除")
        b2.clicked.connect(lambda: self.lst_dict.takeItem(self.lst_dict.currentRow()))
        dh.addWidget(b1)
        dh.addWidget(b2)
        dh.addStretch(1)
        dv.addLayout(dh)

        dv.addWidget(QLabel("变形规则（每个词 × 每条规则）"))
        grid = QGridLayout()
        self.rule_boxes: dict[str, QCheckBox] = {}
        for i, (name, default) in enumerate(RULES):
            cb = QCheckBox(name)
            cb.setChecked(default)
            self.rule_boxes[name] = cb
            grid.addWidget(cb, i // 4, i % 4)
        dv.addLayout(grid)
        dv.addStretch(1)
        self.tabs.addTab(t_dict, "字典攻击")

        # -- 掩码 --
        t_mask = QWidget()
        mv = QVBoxLayout(t_mask)
        mv.addWidget(QLabel("掩码表达式   ?l 小写  ?u 大写  ?d 数字  ?s 符号  ?a 全部  ?1..?4 自定义"))
        self.ed_mask = QLineEdit("?l?l?l?l?d?d")
        self.ed_mask.setFont(QFont("Consolas", 12))
        mv.addWidget(self.ed_mask)
        cb_preset = QComboBox()
        cb_preset.addItem("— 预设 —")
        for name, m in MASK_PRESETS:
            cb_preset.addItem(name, m)
        cb_preset.currentIndexChanged.connect(
            lambda i: self.ed_mask.setText(cb_preset.itemData(i) or self.ed_mask.text()))
        mv.addWidget(cb_preset)
        mv.addWidget(QLabel("自定义字符集 ?1 ?2 ?3 ?4"))
        row = QHBoxLayout()
        self.cs_edits = []
        for i in range(4):
            e = QLineEdit()
            e.setPlaceholderText(f"?{i + 1}")
            e.setMaxLength(64)
            self.cs_edits.append(e)
            row.addWidget(e)
        mv.addLayout(row)
        mv.addStretch(1)
        self.tabs.addTab(t_mask, "掩码攻击")

        # -- 混合 --
        t_hyb = QWidget()
        hv = QVBoxLayout(t_hyb)
        hv.addWidget(QLabel("字典词 + 后缀掩码（用「字典攻击」页的字典）"))
        self.ed_hyb = QLineEdit("?d?d")
        self.ed_hyb.setFont(QFont("Consolas", 12))
        hv.addWidget(self.ed_hyb)
        hv.addWidget(QLabel("例： ?d?d -> password00 … password99"))
        hv.addStretch(1)
        self.tabs.addTab(t_hyb, "混合攻击")

        # -- GPU --
        t_gpu = QWidget()
        gv = QVBoxLayout(t_gpu)
        self.lb_gpu = QLabel("点击下方按钮探测 hashcat")
        self.lb_gpu.setWordWrap(True)
        gv.addWidget(self.lb_gpu)
        bg = QPushButton("探测 GPU 后端")
        bg.clicked.connect(self._probe_gpu)
        gv.addWidget(bg)
        gv.addWidget(QLabel("GPU 模式使用「字典攻击」页的字典，走 hashcat 内核"))
        gv.addStretch(1)
        self.tabs.addTab(t_gpu, "GPU 加速")

        # -- 漏洞攻击 --
        t_kpa = QWidget()
        kv = QVBoxLayout(t_kpa)
        self.tb_pairs = QTableWidget(0, 4)
        self.tb_pairs.setHorizontalHeaderLabels(["可信度", "条目", "明文长度", "来源"])
        self.tb_pairs.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        kv.addWidget(self.tb_pairs)
        kh = QHBoxLayout()
        b_kpa = QPushButton("分析已知明文")
        b_kpa.clicked.connect(self._analyze_kpa)
        b_hash = QPushButton("导出 hashcat hash")
        b_hash.clicked.connect(self._export_hash)
        kh.addWidget(b_kpa)
        kh.addWidget(b_hash)
        kh.addStretch(1)
        kv.addLayout(kh)
        self.tabs.addTab(t_kpa, "漏洞攻击")

        lv.addWidget(self.tabs, 1)

        # 参数 + 按钮
        box_run = QGroupBox("执行")
        rv = QVBoxLayout(box_run)
        rh = QHBoxLayout()
        rh.addWidget(QLabel("线程"))
        self.sp_threads = QSpinBox()
        self.sp_threads.setRange(1, 256)
        self.sp_threads.setValue(os.cpu_count() or 8)
        rh.addWidget(self.sp_threads)
        rh.addWidget(QLabel("最小长度"))
        self.sp_min = QSpinBox()
        self.sp_min.setRange(0, 64)
        rh.addWidget(self.sp_min)
        rh.addWidget(QLabel("最大长度"))
        self.sp_max = QSpinBox()
        self.sp_max.setRange(0, 128)
        rh.addWidget(self.sp_max)
        rh.addStretch(1)
        rv.addLayout(rh)

        bh = QHBoxLayout()
        self.btn_start = QPushButton("开始破解")
        self.btn_start.setObjectName("primary")
        self.btn_start.clicked.connect(self._start)
        self.btn_stop = QPushButton("停止")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)
        bh.addWidget(self.btn_start)
        bh.addWidget(self.btn_stop)
        rv.addLayout(bh)
        lv.addWidget(box_run)

        split.addWidget(left)

        # 右侧输出
        right = QWidget()
        rvo = QVBoxLayout(right)
        rvo.setContentsMargins(0, 0, 0, 0)

        self.lb_result = QLabel("就绪")
        self.lb_result.setObjectName("result")
        self.lb_result.setAlignment(Qt.AlignCenter)
        self.lb_result.setMinimumHeight(48)
        rvo.addWidget(self.lb_result)

        self.pb = QProgressBar()
        self.pb.setRange(0, 100)
        rvo.addWidget(self.pb)

        self.lb_stat = QLabel("—")
        rvo.addWidget(self.lb_stat)

        self.txt = QPlainTextEdit()
        self.txt.setReadOnly(True)
        self.txt.setFont(QFont("Consolas", 9))
        rvo.addWidget(self.txt, 1)

        split.addWidget(right)
        split.setSizes([420, 700])
        root.addWidget(split, 1)
        self.statusBar().showMessage("就绪")

    # ---------------- 事件 ----------------
    def _log(self, s: str) -> None:
        self.txt.appendPlainText(s)

    def _pick_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择压缩包", "",
            "压缩包 (*.zip *.rar *.7z *.jar *.docx *.xlsx *.apk);;所有文件 (*.*)")
        if not path:
            return
        self.ed_path.setText(path)
        self._load_info(path)

    def _load_info(self, path: str) -> None:
        info = self.core.info(path)
        self.archive = info
        if not info.get("ok"):
            self.lb_info.setText("解析失败")
            return
        files = info.get("files", [])
        enc_lines = [f for f in files if f.get("enc") != "none"]
        desc = (
            f"<b>{info.get('format_desc','?')}</b> &nbsp; 条目 {info.get('entries')} "
            f"（加密 {info.get('encrypted')}）<br>"
            f"加密方案：{enc_lines[0]['enc_desc'] if enc_lines else '无'}"
        )
        if enc_lines:
            desc += "<br><br>加密条目：<br>" + "<br>".join(
                f"· {f['name']} <span style='color:#888'>({f['usize']} B)</span>"
                for f in enc_lines[:6])
        self.lb_info.setText(desc)
        self._log(f"[+] 载入 {path}")
        self._log(f"    容器={info.get('format')}  条目={info.get('entries')}  "
                  f"加密={info.get('encrypted')}")
        if not info.get("native_cpu"):
            self._log("[i] 该容器不走原生 CPU 引擎，建议切到 GPU 加速页")
        self._analyze_kpa(silent=True)

    def _add_dict(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "选择字典文件", "", "文本文件 (*.txt *.lst *.dic);;所有文件 (*.*)")
        for p in paths:
            self.lst_dict.addItem(QListWidgetItem(p))

    def _selftest(self) -> None:
        if not self.core.ok:
            return
        rep = self.core.selftest()
        self._log("=== 密码学官方向量自测 ===")
        for line in rep.splitlines():
            self._log("  " + line)

    def _probe_gpu(self) -> None:
        if not self.core.ok:
            return
        g = self.core.gpu_info()
        if not g.get("available"):
            self.lb_gpu.setText("hashcat 不可用：" + g.get("note", ""))
            return
        devs = g.get("devices") or []
        html = (f"<b>hashcat 可用</b><br>{g.get('exe')}<br>"
                f"{g.get('version','')}<br><br><b>设备</b><br>")
        html += "<br>".join(f"· {d}" for d in devs) if devs else "（未解析到设备）"
        self.lb_gpu.setText(html)
        self._log(f"[+] GPU: {g.get('exe')}")
        for d in devs:
            self._log(f"    设备: {d}")

    def _analyze_kpa(self, silent: bool = False) -> None:
        path = self.ed_path.text()
        if not path or not self.core.ok:
            return
        pairs = self.core.pairs(path)
        self.tb_pairs.setRowCount(0)
        for p in pairs:
            r = self.tb_pairs.rowCount()
            self.tb_pairs.insertRow(r)
            self.tb_pairs.setItem(r, 0, QTableWidgetItem(f"{p.get('confidence',0):.2f}"))
            self.tb_pairs.setItem(r, 1, QTableWidgetItem(p.get("entry", "")))
            self.tb_pairs.setItem(r, 2, QTableWidgetItem(str(p.get("len", 0))))
            self.tb_pairs.setItem(r, 3, QTableWidgetItem(p.get("label", "")))
        if not silent:
            self._log(f"[+] 已知明文素材: {len(pairs)} 组")
            for p in pairs:
                self._log(f"    {p.get('confidence'):.2f}  {p.get('label')}  ({p.get('len')} B)")
            self._log("")
            self._log(self.core.report(path))

    def _export_hash(self) -> None:
        path = self.ed_path.text()
        if not path or not self.core.ok:
            return
        h = self.core.export_hash(path)
        self._log("=== hashcat hash ===")
        self._log(h if len(h) < 4000 else h[:4000] + f"…（共 {len(h)} 字符）")
        QApplication.clipboard().setText(h)
        self._log("（已复制到剪贴板）")

    def _build_cfg(self) -> str:
        tab = self.tabs.currentIndex()
        dicts = [self.lst_dict.item(i).text() for i in range(self.lst_dict.count())]
        rules = [n for n, cb in self.rule_boxes.items() if cb.isChecked()]
        parts = []
        if tab == 1:
            parts.append("mode=mask")
            parts.append("mask=" + self.ed_mask.text())
        elif tab == 2:
            parts.append("mode=hybrid")
            parts.append("hybrid=" + self.ed_hyb.text())
        else:
            parts.append("mode=dict")
        if dicts:
            parts.append("dicts=" + ",".join(dicts))
        if rules:
            parts.append("rules=" + ",".join(rules))
        for i, e in enumerate(self.cs_edits):
            if e.text():
                parts.append(f"cs{i + 1}={e.text()}")
        parts.append(f"threads={self.sp_threads.value()}")
        if self.sp_min.value():
            parts.append(f"min={self.sp_min.value()}")
        if self.sp_max.value():
            parts.append(f"max={self.sp_max.value()}")
        return ";".join(parts)

    def _start(self) -> None:
        path = self.ed_path.text()
        if not path:
            QMessageBox.information(self, "提示", "请先选择压缩包")
            return
        tab = self.tabs.currentIndex()
        gpu = tab == 3
        if tab != 1 and self.lst_dict.count() == 0:
            QMessageBox.information(self, "提示", "请先在「字典攻击」页添加字典文件")
            return
        cfg = self._build_cfg()
        self._log(f"[>] 配置: {cfg}")
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.pb.setRange(0, 0 if not gpu else 100)
        self.lb_result.setText("运行中…")
        self.lb_result.setStyleSheet("")
        self.t0 = time.time()
        self.last_tried = 0
        self.worker = CrackWorker(self.core, path, cfg, gpu, self.events)
        self.worker.start()
        self.statusBar().showMessage("破解中…")

    def _stop(self) -> None:
        if self.worker:
            self.worker.stop()
            self._log("[!] 已请求停止…")
            self.statusBar().showMessage("正在停止…")

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "progress":
                    tried, total, speed = payload
                    if total:
                        self.pb.setRange(0, 1000)
                        self.pb.setValue(int(1000 * tried / total))
                        pct = f"{100.0 * tried / total:.2f}%"
                    else:
                        self.pb.setRange(0, 0)
                        pct = "—"
                    eta = ""
                    if speed > 0 and total and total > tried:
                        rem = (total - tried) / speed
                        eta = f"   ETA {int(rem // 3600)}h{int(rem % 3600 // 60):02d}m{int(rem % 60):02d}s"
                    self.lb_stat.setText(
                        f"已尝试 {tried:,} / {total:,}  ({pct})   "
                        f"{speed/1e6:.2f} M候选/秒   {time.time() - self.t0:.1f}s{eta}")
                else:
                    found, msg = payload
                    self.btn_start.setEnabled(True)
                    self.btn_stop.setEnabled(False)
                    self.pb.setRange(0, 100)
                    self.pb.setValue(100)
                    if found:
                        self.lb_result.setText(f"✔ 命中口令：{msg}")
                        self.lb_result.setStyleSheet(
                            "background:#12391f;color:#6ee787;font-size:16px;border-radius:6px;")
                        self._log(f"[✔] 命中: {msg}")
                        QApplication.clipboard().setText(msg)
                        self._log("（已复制到剪贴板）")
                    else:
                        self.lb_result.setText("✘ 未命中")
                        self.lb_result.setStyleSheet(
                            "background:#3d1a1a;color:#ff9d9d;font-size:16px;border-radius:6px;")
                        self._log(f"[✘] {msg}")
                    self.statusBar().showMessage("完成")
                    self.worker = None
        except queue.Empty:
            pass


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("ZipPwn")
    qss = _find_file("theme.qss")
    if qss:
        with open(qss, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
    core = Core()
    w = MainWindow(core)
    w.show()
    # 支持 `python -m zippwn.gui.app 目标.zip` 直接载入
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        w.ed_path.setText(sys.argv[1])
        w._load_info(sys.argv[1])
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
