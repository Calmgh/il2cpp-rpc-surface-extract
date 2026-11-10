---
name: il2cpp-rpc-surface-extract
description: 从 IL2CPP 游戏（Unity + GameAssembly.dll）的配套 PDB 全量导出符号表，定位 RPC 注册表静态构造器，产出「methodId ↔ RemoteCall 函数」完整映射与客户端 RPC 攻击面清单。当需要枚举某 IL2CPP 游戏的 RPC 攻击面、把抓包得到的 methodId 翻译成函数名、或需要 RVA→符号名 的本地快速查询（IDA 不可用 / 卡死）时使用。也适用于排查「IDA MCP list_funcs 在巨型 IDB 上卡死」「.nam 被独占锁读不了」「capstone 反汇编返回 0 条」等问题。
description_zh: IL2CPP RPC 攻击面提取
description_en: IL2CPP RPC surface extraction
---

# il2cpp-rpc-surface-extract

从 PDB 出发，一次性拿到 IL2CPP 游戏的**全量符号表**与**完整 RPC 攻击面（含 methodId 绑定）**。
整个过程**不依赖 IDA**（IDA 只用于可选的反编译），实测在 179 MB / 90 万函数的目标上
全流程约 5 分钟。

## When to use

- 需要某 IL2CPP 游戏的**完整客户端 RPC 清单**（攻击面枚举、排测试优先级）
- 抓包拿到一个 `methodId`，想知道它对应哪个 `RemoteCall*` 函数
- 需要在 5 秒内完成 **RVA → 函数名** 查询（不想开 IDA）
- **IDA MCP 的 `list_funcs` / `func_query` 在巨型 IDB 上卡死**（50 万+ 函数时会阻塞主线程数分钟）
- 需要确认某个 RVA 在**当前 build** 下是否还对（符号表可交叉验证）

**前置条件**：目标目录下同时存在 `GameAssembly.dll` 与其**同 build 的 `GameAssembly.pdb`**。
没有 PDB 时本 skill 不适用（改用字节特征定位法）。

## Tools

| 工具 | 作用 |
|---|---|
| `tools/export_symbols.py` | PDB → 符号表（Windows 走 dbghelp，带函数/数据分类；`--from-pdb` 为跨平台回退） |
| `tools/rpc_registry.py` | 定位 `*RpcInfo__cctor`，提取注册表 methodId 全集 |
| `tools/rpc_map.py` | `*_RemoteCall*` ↔ methodId 绑定，按组件分组 |
| `tools/rva_query.py` | RVA 精确查 / owner 反查 / 名字搜索 |
| `tools/find_callers.py` | 扫全部可执行节，找 CALL/JMP 调用点 |
| `tools/func_cmp.py` | 两函数字节级对比，判定是否同构 |
| `tools/check_entry.py` | 入口字节、序言、可打 5 字节跳转的校验 |
| `tools/metadata_dump.py` | `global-metadata.dat` 字符串堆邻域导出 |

## Steps

### 1. 确认 PDB 与 DLL 同 build

```bash
ls -la <分析目录>/         # 应同时看到 GameAssembly.dll 与 GameAssembly.pdb
```

PE 指纹应一致：`TimeDateStamp`（`e_lfanew+8`）+ `SizeOfImage`（可选头 `+56`）。
**只比这两项，不要比文件大小** —— 不同副本的文件大小常因签名/压缩而不同，
而两次不同链接的构建可能恰好大小一样。

### 2. 全量导出符号

```bash
python tools/export_symbols.py GameAssembly.dll --out sym
```

产出三张表：

| 文件 | 过滤条件 | 用途 |
|---|---|---|
| `sym.tsv` | 全部 | 全量（含数据符号） |
| `sym_funcs.tsv` | tag 5 | **函数名 → RVA，主力查询表** |
| `sym_methvars.tsv` | tag 7 且名以 `_RuntimeMethod_var` 结尾 | il2cpp 方法元数据变量 |

行格式：`0x<RVA>\t0x<size>\t<tag>\t<name>`。

> ⚠️ 用 `--mask` 可过滤（如 `*Vehicle*`），但 **`mask="*"` 时前 80 万符号 tag 全是 7、
> 函数计数还是 0 是正常现象**（IL2CPP 的 `_RuntimeMethod_var` 排在前面），
> 不要误判为失败。

### 3. 找 RPC 注册表静态构造器

```bash
python tools/rva_query.py --symbols sym_funcs.tsv --search RpcInfo__cctor
```

典型形态（每个实体类型一张表）：

```
0x2B00000  0x1184D  WorldRpcInfo__cctor
0x2B10000  0x0A7E2  ClientRpcInfo__cctor
0x2B20000  0x078CA  UnityDsRpcInfo__cctor
```

这些 `__cctor` 就是注册表本体，`size` 与注册项数成正比（每项约 **0x5A = 90 字节**）。

> 本文所有 RVA / methodId 都是手写示例值，不是任何真实构建的地址。

### 4. 提取注册项

```bash
python tools/rpc_registry.py GameAssembly.dll --symbols sym_funcs.tsv --out registry.tsv
```

工具内部**必须从 `__cctor` 起点顺序反汇编**（非边界起步会失败，见 Pitfalls），
然后在指令流里识别这个序列：

```asm
call il2cpp_object_new                 ; 新建 RpcInfo 对象
mov  rcx, [rip+A]                      ; A = 该 RPC 的字符串字面量
mov  [rdi+0x10], rcx
mov  rdx, [rip+B]
call <runtime_init>                    ; il2cpp_codegen_initialize_runtime_metadata
mov  word [rdi+0x18], 1
mov  r8, rdi                           ; TValue = RpcInfo
mov  r9, [rip+C]                       ; Dictionary_2_Add_RuntimeMethod_var
mov  edx, <methodId>                   ; ← TKey，4 字节小端
mov  rcx, rbx                          ; this = 字典
call <Dictionary_2_Add>
```

判据：`mov edx, imm32` 后紧跟 `mov rcx, <reg>` 再 `call`。
**`methodId` 就是那个 `edx` 立即数**，收全即得注册表全集。

> ⚠️ **handler 方法指针不在静态注册码里**（运行时填充），所以注册表**只能给 methodId 全集，
> 给不了 handler 名**。要函数名请走 Step 5。

### 5. 关联 `RemoteCall*` ↔ methodId

```bash
python tools/rpc_map.py GameAssembly.dll --symbols sym_funcs.tsv --registry registry.tsv
```

思路：**每个 RPC 包装函数会把 methodId 当立即数传给底层发送/记录函数。**

1. 从符号表筛出所有 `*_RemoteCall*` 函数（得 RVA + size）
2. 对每个函数读其字节、反汇编
3. 收集所有 `mov r32, imm32` 的立即数，与 Step 4 的白名单**取交集**
4. 命中者即为该 wrapper 的 methodId

实测命中率 **471/501 ≈ 94%**。剩余未命中多为泛型 / gshared 实例化体 ——
它们的 key 是间接加载的，不嵌在函数体里。

### 5.5 ⭐ 按「业务关键词」回扫 —— 防止类名前缀枚举漏项

按类名前缀枚举（`<Component>_RemoteCall*`）**会漏掉挂在别的类上的同功能 RPC**。

两个真实教训，都值得记住：

**① 前缀陷阱。** 某载具的「进入」动作长期只列了 4 条（`Launch` / `Load` / `Unload` / `Rotate`），
**漏了「上车」** —— 它不在 `Vehicle*` 前缀下，而是挂在 `PlayerEntity` 上，
全名形如 `PlayerEntity_RemoteCallEnterVehicle`。

**② 大小写陷阱，比前缀陷阱更隐蔽。** 首轮 grep 写的是 `Vehicleload`，
而符号名实际是混合大小写的 `VehicleLoad` —— `grep` 默认大小写敏感，
**静默漏项，没有任何报错**。

**正确姿势（两步，都要加 `-i`）**：

```bash
# ① 按业务关键词全库回扫（不限类名前缀）
grep -oiE "[A-Za-z_0-9]*enter[A-Za-z_0-9]*" sym_funcs.tsv \
  | grep -iE "remote|rpc|send" | sort -u

# ② 换维度再扫一遍（载具/座位/挂载等同义词）
grep -iE "RemoteCall.*(Vehicle|Mount|Seat)" sym_funcs.tsv
```

**上线前自检**：枚举结果必须能回答「**这个功能从进入到退出，客户端一共会发几条包？**」
—— 与抓包时序文档逐条比对，**条数对不上就是漏了**。

某载具装载功能的正确答案是 **6 条**（上车 → 瞄准 → 装填 → 发射 → 下车，另加卸载），
旧记录只列了 4 条。

**⚠️ 配套纪律：旧文档里标「未覆盖」的条目要定期回扫。**
上面那个漏项**在旧分析文档里早已写明"未覆盖"**，却一直没被执行 —— **文档写了 ≠ 做了**。
每次开工前，先把项目文档里所有 `未覆盖 / 待测 / ❓` 条目捞出来过一遍。

### 5.6 找到 RPC 后补三问（成本极低、收益极高）

拿到一串 RPC 之后，**不要直接开测**，先补三个"谁在调、谁在读、算不算漏洞"：

**① 真实调用点 → 宿主函数**

```bash
python tools/find_callers.py GameAssembly.dll --symbols sym_funcs.tsv --target 0x1A2B3C0
python tools/rva_query.py --symbols sym_funcs.tsv --owner 0x1C5D2E0
# → UiVehicleContainer_OnIconAcceptDrag  0x1C5D100
```

- 价值：**决定攻击路径**。某载具 `Load`/`Unload` 的真实入口是**拖拽图标**
  （`OnIconAcceptDrag`）而**不是按钮** ⇒ 去点按钮测是白费功夫。
- 价值：**给参数定名**。`Unload` 的宿主是「拖回背包」⇒ 立刻明白它是
  "把已装填的道具取回背包"，"道具复制"假设因此变得具体可测。

**② 服务端同步字段的读点分布（判断某字段能不能当门禁）**

```bash
python tools/find_callers.py GameAssembly.dll --symbols sym_funcs.tsv --target <get_XXX 的 RVA>
```

- **读点全在 UI/Mgr 层** ⇒ 该字段只是**显示/本地拦截**，**发送侧无校验** ⇒ **是候选攻击面**
  （例：`HasAimingModule` 这类开关字段）。
  ⚠️ **"候选"不是"漏洞"** —— 见下方 ④。
- **读点出现在发送函数 / 校验函数里** ⇒ 有客户端校验，需绕过。
- **读点全在 HUD 显示层** ⇒ ⚠️ **该字段不是权限依据**，**不能**用它反推"服务端会校验"
  （例：`CasterPlayerId` 这类字段，读点全在 HUD 显隐逻辑里）
  ⇒ 越权类结论**必须实测**，静态推不出来。

**③ 同族函数同构判定**

```bash
python tools/func_cmp.py GameAssembly.dll 0x1A2B3C0 0x1A2B4F0 --symbols sym_funcs.tsv
# → size 均 0x163，355B 中 26 段差异全是 RIP rel32
#   关键差异 @+0x0E8: mov r9d, 0x????????  ↔  0x????????
```

⇒ 包装函数族常由同一模板生成，**同尺寸 + 差异仅立即数/rel32 = 同构 ⇒ 参数寄存器语义可直接照搬**，
省掉一整轮运行时标定。

**④ 资源/物品类：先验证「归属」概念是否存在**

碰到"公共容器 + 个人资源"型目标（载具弹药架 / 公共仓库 / 共享熔炉），
**不要因为"没有归属校验"就报漏洞**：

```bash
grep -oE "[A-Za-z_0-9]*(Owner|Belong|Loader|Holder|PlayerId)[A-Za-z_0-9]*" sym.tsv | sort -u
```

- 归属相关**三者有其一**（归属字段 / "这是谁的"UI 提示 / 离开时自动退还）⇒ 设计上存在归属约定
  ⇒ **缺校验 = 真漏洞** ✅
- **三者皆无** ⇒ 设计上根本没有归属概念 ⇒ **"不校验"是忠实实现 ⇒ 设计，不报** ❌
  （例：弹药架上的 `CurCount` 是炮台持有的公共同步字段，"装填 = 交付给炮台"。）

### 5.7 ⭐⭐ 枚举之后必须做「触发可达性」检查（比枚举本身更重要）

**枚举出 RPC ≠ 该攻击面可测。** 排优先级之前必须确认「**我的攻击输入能不能被送达这个函数**」。

**反例（真实踩到）**：某载具的 `EnterVehicle`（上车）在攻击面清单里躺了一整天，
看着是"客户端权威 + 无限流 + 位移类"的**最高危害**项。查了调用点才发现：

- **唯一调用点 = 上车按钮的尾调用**（`jmp` 而不是 `call`）
  ⇒ 该按钮只在**交互范围内**出现 ⇒ 「**远程**上车」的攻击语义与「按钮只能在**近处**触发」
  **物理矛盾**；
- 且目标参数来自 **该按钮自身持有的实体**，**不是玩家选的目标** ⇒ 即使能触发，
  改它也**没有第二个候选值**（一局仅一台载具）。

⇒ **对每个候选 RPC 连问三句**：

1. **入口可达吗？** 触发它的 UI/事件在什么前置条件下才出现？我能否绕过该前置条件？
   （若前置条件与攻击语义互斥 ⇒ 该面直接划掉，例如上面的"远程"vs"按钮只在近处"）
2. **参数可控吗？** 要改的参数是**玩家选的**，还是**系统给的固定值**？
   —— 系统固定值 ⇒ 改了也没用（无第二取值）。
3. **有第二个候选值吗？** 单实例对象（一局只有一台的载具/唯一建筑）⇒ 越权/伪造类攻击**天然不成立**。

**检查手段（3 分钟，省掉一整轮白测）**：

```bash
python tools/find_callers.py GameAssembly.dll --symbols sym_funcs.tsv --target 0x2F81B00
python tools/rva_query.py --symbols sym_funcs.tsv --owner 0x2801900
python tools/check_entry.py GameAssembly.dll 0x2801700
```

⇒ **纪律**：答不上这三问的 RPC，先标「**触发可达性未验证**」，**不要**直接排进测试优先级。

### 6. 生成攻击面报告

按组件前缀（`<Component>_RemoteCall<Name>` 的 `<Component>`）分组统计，
按「调试/GM > 权限/领地 > 物品 > 其他」排序，输出 methodId + RVA 表格。

`rpc_map.py` 已经给出按组件的计数，组件 RPC 数越多说明协议越密集，优先读那里。

### 7. 附加技巧：从 `global-metadata.dat` 批量还原类成员名

IL2CPP 的 `<Game>_Data/il2cpp_data/Metadata/global-metadata.dat` 里，
**字符串堆按类型聚集** —— 同一个类的**方法名、字段名、attribute 名、枚举值名连续排列**。

```bash
python tools/metadata_dump.py global-metadata.dat --anchor AddStyleRank --classify
```

只要定位到目标类的**任意一个成员名字符串偏移**，向两侧 dump 几百字节、按 `\x00` 切分，
就能**批量还原整类成员**。

**价值**：能直接拿到**反编译看不全**的信息 —— 例如枚举的取值（`Publish` / `Dev`）、
attribute 类名与字段名（决定指令分类与权限分级）、UI 分组字段等。
比逐个反编译猜名字快一个数量级。

## Pitfalls

- **IDA MCP 的 `list_funcs` / `func_query` 在巨型 IDB 上会卡死**。
  其内部实现是 `[get_function(a) for a in idautils.Functions()]`，58 万函数时跑数百秒
  且**阻塞 IDA 主线程**（后续所有 RPC 排队，连 `server_health` 都从 0.6s 劣化到 15s）。
  **只能按地址精确查询**：`lookup_funcs`、`decompile`/`disasm`、`xrefs_to`。
  按名字搜函数一律用本地 `*_funcs.tsv` grep。
- **IDA 的 `.nam` 文件被独占锁**，IDA 运行期间读不到 → 必须走 dbghelp 或纯 Python 解析。
- **capstone 从非指令边界起步时，若首字节是无效指令（x64 下 `0x07`）会直接返回 0 条指令**。
  必须先从函数/区间**起点**顺序反汇编得到完整列表，再按地址索引上下文。
- **符号表可能含负数地址**（如 `0x-17FFFFFFC`），解析时必须 `try/except` + 范围过滤。
- **`_m<HASH>` 后缀要去掉**才能得到可读类名（`il2cpprpc.dbghelp.strip_hashes`）。
- **不要用 `nohup ... &` 起长任务**：进程会随 shell 会话被清理（日志停更、无结束标记）。
  全量导出实测只要 60~90 秒，直接前台跑即可。
- **`mask` 只能单个 glob**，不能做多模式或"排除"。要按 tag 过滤请在回调里判 `Tag`。
- 注册项字节模式 `BA <mid:4> 48 8B CB E8` 全库扫描会**大量误报**（小整数 methodId 碰撞，
  实测 `0x1` 命中 806 次）。**该模式只能作旁证，注册表必须以 Step 3/4 为准**。
- 🔴 **枚举 RPC 一律加 `-i`，且不要只按类名前缀扫**：
  ① **大小写**：符号名可能是 `VehicleLoad` 而非 `Vehicleload`，`grep` 默认大小写敏感 ⇒ **静默漏项**；
  ② **前缀**：同功能 RPC 可能挂在别的类上（上车挂在 `PlayerEntity`，不是 `Vehicle*`）。
  ⇒ 必须按**业务关键词**全库回扫，并用「抓包时序条数」做交叉校验（详见 §5.5）。
- 🔴 **旧文档里的 RVA 必须现场复核**：旧记录可能混了 build 或含手误
  ⇒ 用 `tools/check_entry.py <dll> <RVA>` 验一遍入口字节再采信。
- ⭐ **文档里的"未覆盖""待测"标记要定期回扫**：漏项在旧文档里**早就写明"未覆盖"**，
  却一直没执行。⇒ **文档写了 ≠ 做了**。

更细的环境与工具坑见 `references/pitfalls.md`。

## Verification

1. **符号量级自检**：正常 IL2CPP 项目函数符号数在 30 万~100 万量级；
   若只有几百条，说明 mask 写错或 PDB 不匹配。
2. **base 一致性**：`SymLoadModuleEx` 返回的 base 应与 IDA 的 `imagebase` 一致
   （常见 `0x180000000`）。
3. **动态标定（最强验证）**：拿**抓包已确认**的 methodId 去查表，函数名必须与抓包语义吻合。
   例如抓包显示某个 key 触发的行为是"拆分物品"，查表就应命中 `SplitItem` 这一类命名。
   若已知 methodId 全部命中 → 整表可信；若有偏差 → PDB 与该 build 不匹配，回 Step 1。
4. **RVA 抽验**：随机取一个函数名+size，用 `tools/check_entry.py` 确认该区间确实是函数序言
   （`48 89 5C 24` / `40 53` / `55 48 8B EC`），而非 `00` / `CC`。

## References

- 环境与工具细节坑：`references/pitfalls.md`
- 下游动作（服务端是否校验某个 RPC）不在本 skill 范围：本 skill 只产出**候选清单**，
  「能不能绕过」必须实测
