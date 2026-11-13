"""ZipPwn —— 压缩包口令恢复 / 取证工作台。

模块划分：
    zippwn.engine.crypto      底层密码学（CRC32 / AES / PBKDF2）
    zippwn.engine.zipfmt      压缩包结构解析、加密参数提取、已知明文采集
    zippwn.engine.checkers    各类加密方案的候选口令校验器（向量化）
    zippwn.engine.candidates  候选口令生成（字典 / 规则变换 / 掩码 / 混合）
    zippwn.engine.kpa         已知明文攻击（Biham-Kocher 路线）
    zippwn.engine.gpu         hashcat GPU 后端桥接
    zippwn.engine.runner      多进程调度、进度、断点续跑
    zippwn.gui.app            PySide6 图形界面
"""

__version__ = "0.4.0"
__all__ = ["__version__"]
