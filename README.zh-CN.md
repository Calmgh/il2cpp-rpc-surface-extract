# il2cpp-rpc-surface-extract

**从 PDB 还原 IL2CPP 游戏的客户端 RPC 攻击面。** 不开 IDA，不用反汇编 GUI。
一个 179 MB / 90 万函数的 `GameAssembly.dll`，全流程约五分钟。

只要手上有 `GameAssembly.dll` 和**同 build 的** `GameAssembly.pdb`，就能拿到：

* **全量符号表** —— 函数名 ↔ RVA，毫秒级查询
* 每张 RPC 注册表的**完整 methodId 集合**，从 `*RpcInfo__cctor` 初始化代码里读出来
* **`methodId` ↔ `*_RemoteCall*` 绑定**（实测覆盖率约 94%）
* 每个 wrapper 的**调用关系** —— 这才是决定「入口到底可不可达」的东西

同时它也是一份写下来的判断依据：什么样的 RPC 值得测，以及枚举会在哪三个地方
**静默漏项**。

```console
$ python tools/rpc_map.py GameAssembly.dll --symbols sym_funcs.tsv --registry registry.tsv
symbols        : 1723401
registry keys  : 1249
wrappers       : 501  (pattern '_RemoteCall', case-insensitive)
bound          : 471 wrappers (94.0%)
bindings       : 471

methodId     wrapper
0x11111111   ?WorldEntity_RemoteCallDoThing@UWorldEntity@@QEAAXXZ
...
```

---

## 为什么做这个

IDA 适合精读一个函数，不适合回答「这 500 个 wrapper 里哪几个值得先看」。
180 MB 的 IL2CPP 模块光是打开就要几分钟；让 MCP 桥去枚举函数，查询跑在 IDA
主线程上，又会再卡几分钟。

而排优先级需要的东西，PDB 里全都有：名字、RVA、大小。注册表的构造函数就是
普通的线性代码，四十行反汇编循环就能读完。所以这套工具读 PDB、解构造函数，
把 IDA 留给真正需要精读的那几个函数。

## 安装

```bash
git clone https://github.com/Calmgh/il2cpp-rpc-surface-extract
cd il2cpp-rpc-surface-extract
pip install -r requirements.txt   # capstone，只有分析需要，导出符号不需要
```

Python 3.8+。符号导出走 Windows 自带的 `dbghelp`；跨平台可用 `--from-pdb`
回退，但那条路径无法区分函数与数据符号。

## 快速开始

```bash
# 1. 名字 ↔ RVA
python tools/export_symbols.py GameAssembly.dll --out sym

# 2. 注册表与它的 methodId 全集
python tools/rpc_registry.py GameAssembly.dll --symbols sym_funcs.tsv --out registry.tsv

# 3. 哪个 wrapper 发哪个 key
python tools/rpc_map.py GameAssembly.dll --symbols sym_funcs.tsv --registry registry.tsv

# 4. 这个 wrapper 可达吗？谁在调？
python tools/find_callers.py GameAssembly.dll --symbols sym_funcs.tsv --target 0x1A2B3C0
```

## 工具一览

| 工具 | 回答什么问题 |
|---|---|
| `export_symbols.py` | 这个模块里有什么？（名字、RVA、大小、函数还是数据） |
| `rpc_registry.py` | 哪些 methodId 是合法的？ |
| `rpc_map.py` | methodId X 是哪个客户端函数发的？ |
| `rva_query.py` | 这个地址属于哪个函数？ |
| `find_callers.py` | 谁调用了这个函数？ |
| `func_cmp.py` | 这两个函数是不是同一个模板？ |
| `check_entry.py` | 这个 RVA 在当前 build 上真的是函数入口吗？ |
| `metadata_dump.py` | 这个类还有哪些成员？（字符串堆邻域） |

每个都能独立运行、输出可读；`find_callers` / `func_cmp` / `check_entry` 支持
`--json` 以便脚本消费。

## 比工具更重要的判断

枚举 RPC 是容易的一半。难的是判断哪些值得测。三种踩过的坑，都真实消耗过时间：

**枚举会静默漏项。** 按类名前缀过滤，会漏掉挂在别的类上的 RPC —— 某个载具的
动作可能挂在 `PlayerEntity` 上而不是 `Vehicle*` 下。另外符号名会混用大小写
（`VehicleLoad` 旁边就是 `VehicleLOad`），`grep` 默认大小写敏感，**漏了不报错**。
两个坑都靠「按业务关键词 + `-i` 全库回扫」，再用「这个功能从头到尾发几条包」
去交叉校验。

**可达性比危害等级更重要。** 一个看起来完美的目标 —— 客户端权威、无限流、位移类
—— 如果唯一调用点是「只在近处才会出现的按钮」，那"远程"这个前提就和"只能近处
触发"物理矛盾，整条都白测。三个问题能滤掉大部分：**入口可达吗？参数是玩家选的
吗？有第二个候选值吗？** 单实例对象没有第二个值可以伪造。

**"没有归属校验"不等于漏洞。** 对公共容器（弹药架、公共仓库、共享熔炉），先确认
「归属」这个概念到底存不存在：没有归属字段、没有"这是谁的"UI、离开也不自动退还
—— 那就是设计上根本没有归属概念，不校验是**忠实实现**，不是漏洞。

完整工作流、`Dictionary.Add` 序列的寄存器级细节、每一项检查背后的推理，都在
**[SKILL.md](SKILL.md)**。它按 Claude skill 的格式写：把整个目录丢进 skills 目录，
agent 就能直接用。

## 注册表是怎么读出来的

生成的代码，一条一条：

```asm
mov  r8, rdi            ; value  = RpcInfo
mov  r9, [rip+C]        ; method = Dictionary_2_Add_RuntimeMethod_var
mov  edx, <methodId>    ; key    <-- 要的就是这个
mov  rcx, rbx           ; this   = 字典
call <Dictionary_2_Add>
```

把所有「两条指令后跟 `call`」的 `mov edx, imm32` 收齐，就是这张表的 key 全集。
handler 指针**不在**这里 —— 它是运行时填充的 —— 这正是第三步存在的理由：
wrapper 函数会把自己的 key 当立即数嵌进函数体，两个集合取交集就得到绑定关系。

## 与 `pdb-symbol-extract` 的关系

[`pdb-symbol-extract`](https://github.com/Calmgh/pdb-symbol-extract) 是更底一层：
纯 Python 的 MSF/PDB 读取器，不依赖 Windows。本项目内嵌了它的精简版作为跨平台
路径，并在上面加了分析层。只需要从任意 PDB 提符号表 → 用那个；需要 IL2CPP 的
RPC 攻击面 → 用这个。

## 范围与边界

这是**对本地已有二进制的静态分析**。不附加进程、不发流量、不改内存、不连服务器。

它不做的事：

* **不判断服务端有没有校验。** 它产出候选清单。某条 RPC 能不能利用是运行时问题，
  必须在授权环境里单独实测。
* **不覆盖静态/内部函数。** 只有公有符号；那些要走模块流或运行期特征扫描。
* **不做反编译。** `func_cmp` 比的是字节和指令，不是逻辑。要读一个函数，用 IDA ——
  那正是它擅长的。

请只在自有或已获授权的目标上使用。

## 测试

测试用例**从零拼**一个 IL2CPP 风格的模块 —— 一个含四个手写机器码函数的 PE、
一个配套 PDB、一份 metadata 字符串堆 —— 然后把每条解析路径都跑一遍。
不依赖任何第三方二进制，仓库里不存 fixture。

```bash
python -m unittest discover -s tests -v
```

覆盖：容器解析、符号分类、RVA/owner 查询、注册表 key 提取、wrapper 绑定与未命中
路径、调用点扫描、同构判定、入口启发式、metadata 字符串邻域。

## 这些知识从哪来

IL2CPP 元数据布局和 PDB 格式在
[Il2CppDumper](https://github.com/Perfare/Il2CppDumper)、LLVM 的
`DebugInfo/MSF` 与 `DebugInfo/CodeView`，以及一堆小工具里都能查到。
这个仓库新的部分比较窄：从生成的构造函数里读出 RPC 注册表的 key 全集（不依赖
运行时），以及围绕「拿到清单之后怎么筛」的那套纪律。

## 许可

MIT，见 [LICENSE](LICENSE)。
