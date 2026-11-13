# 免责声明 / Disclaimer

> 最后更新：2026-11-13

---

## 中文

**ZipPwn 是安全研究与数字取证工具**，设计用途是在**已获得合法授权**的前提下：

- 恢复自己或客户所属压缩包的口令（忘记密码、遗留归档、离职交接）
- 评估现有归档口令策略的强度
- 验证备份与加密方案是否可靠
- 安全教学与 CTF 竞赛

**使用本工具即表示你确认并同意以下几点：**

1. **仅限授权范围**
   你只对**自有资产**、或持有**明确书面授权**的目标使用本工具。对第三方系统、数据或设备使用时，
   必须事先取得其所有者或管理者的合法授权。

2. **禁止的用途**
   不得将本工具用于：未授权访问他人数据；规避技术保护措施；窃取商业秘密、个人信息或其他受法律保护的
   数据；任何违反所在国家或地区法律法规的行为。

3. **责任自负**
   使用者对所进行的一切操作及其后果承担**全部责任**。作者与贡献者不对任何人因使用或误用本工具
   造成的直接或间接损失、法律责任、行政处罚或声誉损害承担责任。

4. **按原样提供**
   本软件依据 MIT 许可证"按原样"提供，不附带任何明示或默示担保，包括但不限于适销性、
   特定用途适用性与非侵权担保。见 [LICENSE](LICENSE)。

5. **不提供针对性协助**
   作者不提供针对特定第三方目标的攻击服务、数据，也不协助规避任何司法辖区的法律限制。

6. **不收集数据**
   本工具完全在本地运行，不向任何服务器回传口令、文件名或统计信息。
   GPU 后端调用的 hashcat 为独立开源项目，其行为以其自身许可与文档为准。

---

## English

**ZipPwn is a security research and digital forensics tool.** It is intended to be used **only with
proper authorization**, for:

- recovering passwords for archives you own or are contracted to recover
- assessing the strength of your own archive password policies
- validating that backup and encryption schemes actually hold up
- security education and CTF competitions

**By using this tool you confirm and agree that:**

1. **Authorized scope only.** You will use ZipPwn solely against assets you own, or targets for which
   you hold explicit written authorization. Use against third-party systems, data, or devices requires
   prior lawful authorization from their owner or administrator.

2. **Prohibited uses.** You will not use this tool for unauthorized access to data belonging to others,
   circumvention of technical protection measures, misappropriation of trade secrets, personal data, or
   any other legally protected information, or any activity that violates applicable law.

3. **You are responsible.** The user bears **full responsibility** for all actions taken and their
   consequences. The authors and contributors accept no liability for any direct or indirect loss,
   legal liability, regulatory penalty, or reputational harm arising from the use or misuse of this
   software.

4. **Provided "as is".** This software is distributed under the MIT License, without warranty of any
   kind, express or implied, including but not limited to the warranties of merchantability, fitness
   for a particular purpose, and noninfringement. See [LICENSE](LICENSE).

5. **No targeted assistance.** The authors do not provide attack services or data targeting specific
   third parties, and do not assist in evading legal restrictions in any jurisdiction.

6. **No data collection.** ZipPwn runs entirely locally. It does not transmit passwords, filenames, or
   telemetry to any server. The optional GPU backend invokes hashcat, an independent open-source
   project governed by its own license and documentation.

---

## 使用边界一览 / Scope at a glance

| 场景 Scenario | 允许 Allowed |
|---|---|
| 破解自己忘记密码的备份 | ✅ |
| 客户书面授权下的取证 | ✅ |
| 评估公司归档口令强度 | ✅ |
| CTF / 教学实验 | ✅ |
| 破解下载来的他人压缩包 | ❌ |
| 未授权访问他人设备或网盘 | ❌ |
| 规避 DRM / 技术保护措施 | ❌ |
