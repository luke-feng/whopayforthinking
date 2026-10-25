# 四模型原生生成配置审计与字段契约

2026-10-11，落实 `review/supervisor-decision-thinking-mode-config-2026-10-11.md` 及最新补充；2026-10-12参数包审查通过，见 `review/native-generation-config-round1-review.md`，审核提交为 `0ef49217f25efd280c247c000de2d3ea9b309077`。**通过范围仅限CPU来源审计、采样参数与记录接口；不是规则v3、封装或执行审批。新旧准入和主采集执行仍被当前collector的发布闸阻止。** 预算状态机、统一新运行SHA、固定哈希审批和owner封装在下一包交审，相关实现获审后才能prepare第一档；执行仍需owner显式审批。本页没有GPU执行命令。

## 固定版本与来源

完整逐文件URL、大小、SHA256和上游Git blob/LFS核对见 `data/calibration/native-mode-source-audit-2026-10-11.json`，SHA256 `371bcd3035145b3c703c12f7faa8711e19b901828c7b752b1d809c49390cebe0`。公开原文缓存位于 `work/calibration/native-mode-audit-20261011-v2`，只下载模型卡、模板、tokenizer配置和生成配置，没有权重、模型代码或推理执行。

| 模型 | 固定revision | 配置来源 |
| --- | --- | --- |
| Qwen3.8-27B | 1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0 | [模型卡](https://huggingface.co/Qwen/Qwen3.8-27B/blob/1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0/README.md)、独立chat_template、generation_config |
| Qwen3.5-9B | c202236235762e1c871ad0ccb60c8ee5ba337b9a | [模型卡](https://huggingface.co/Qwen/Qwen3.5-9B/blob/c202236235762e1c871ad0ccb60c8ee5ba337b9a/README.md)、独立chat_template；该revision没有generation_config.json |
| Nemotron-3-Nano-30B-A3B-BF16 | bf77c3174f68ad409e1c2aa60daeb46e32d1c606 | [模型卡](https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16/blob/bf77c3174f68ad409e1c2aa60daeb46e32d1c606/README.md)、独立chat_template、generation_config |
| Qwen2.5-Coder-7B-Instruct | c03e6d358207e414f1eca0bb1891e29f1db0e242 | [模型卡](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct/blob/c03e6d358207e414f1eca0bb1891e29f1db0e242/README.md)、tokenizer_config内嵌模板、generation_config |

Qwen3.8、Nemotron和Coder的小配置文件SHA256另与已回传集群assets.lock逐项相同。Qwen3.5尚无owner资产锁回传，本轮只能核固定上游revision；未来worker会在加载模型前核本地小文件哈希，不能把上游检查称为已验证集群模型本体。首次下载审计遇到Qwen3.5缺文件时停止，未猜配置；首次部分目录保留，新目录中明确将其记为absent。

## 本包选用的显式采样

| 分层 | temperature | top_p | top_k | min_p | presence_penalty | repetition_penalty | 模板参数 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| q38-thinking | 1.0 | 0.95 | 20 | 0 | 0 | 1.0 | enable_thinking=true，reasoning_effort=medium；按v3路径才能改low；preserve_thinking=true |
| q38-nonthinking | 0.7 | 0.80 | 20 | 0 | 1.5 | 1.0 | enable_thinking=false，preserve_thinking=true |
| q35-thinking | 1.0 | 0.95 | 20 | 0 | 1.5 | 1.0 | enable_thinking=true；无强度参数 |
| nemotron-thinking | 1.0 | 1.0 | 0 | 0 | 0 | 1.0 | enable_thinking=true；不用reasoning_budget |
| coder-nonthinking | 0.7 | 0.80 | 20 | 0 | 0 | 1.1 | 空参数字典，无原生thinking |

各层frequency_penalty显式0；请求还显式n=1、min_tokens=0、ignore_eos=false、无额外stop列表、thinking_token_budget=null，EOS仍由模型配置/分词器原生处理。Nemotron未规定的top_k/惩罚，以及Coder未规定的min_p/presence/frequency，选择中性值并作为本协议决策记录，**不冒称厂商明确推荐**。top_k=0在固定vLLM中表示不做top-k截断。

Qwen3.8两种模式的六项值来自同版模型卡。Qwen3.5通用thinking预设按supervisor选择，不套用其WebDev类精确编码预设（后者temperature0.6、presence0）。Coder模型卡quickstart调用model.generate并沿用生成配置，没有另列采样推荐表；因此Coder四个非中性值来自固定generation_config，而不是从quickstart的512 token例子推导。

## 未选用的模式与原生控制边界

- Qwen3.8模板支持xhigh/medium/low。默认xhigh注入高强度指令，low注入简短聚焦指令，medium不注入这两段；本包显式传medium/low并校验实际system部分，拒绝静默落回xhigh。关闭模板预置已闭合thinking标记。preserve_thinking只涉及历史消息，本实验只有system+user，不作多轮强度效果解释。
- Qwen3.5仅用enable_thinking开关，没有reasoning_effort。其非thinking通用预设是0.7/0.8/top_k20/presence1.5。模型卡非thinking reasoning预设在API提示处与Best Practices处不一致：前者1.0/0.95/top_k20/presence1.5，后者1.0/1.0/top_k40/presence2；该模式不在本面板，记录差异，不自行合成唯一推荐值。
- Nemotron模板有enable_thinking与默认截去历史thinking的行为，没有medium/low档位。reasoning任务推荐1.0/1.0；文档另列tool calling的0.6/0.95，但不能把它当作单独的非thinking推荐预设。关闭模式有模板开关，未见专门的关闭模式采样表。
- Nemotron模型卡的reasoning_budget是客户端预算/强制收束示例：先生成思考，必要时补闭合标记后再调一次生成答案，不是模板里的强度参数。本协议明确不传、不实现两调用预算，避免某一模型改变截断与交付机制。
- Coder没有原生thinking开关/强度层。新采样不追溯改变旧Coder技术pilot或收尾验收原件。

## 输出长度推荐的语境

| 模型 | 文档说法 | 本实验解释 |
| --- | --- | --- |
| Qwen3.8 | 在1M上下文、支持分别限制reasoning/final的agentic框架中，建议reasoning262144、final131072；原生上下文262144 | 不是每道LCB题的必要输出量，也不是本单调用total-output cap。新阶梯属于明确受限预算，不能称全面复刻最高性能推荐 |
| Qwen3.5 | 多数查询32768；复杂数学与编程竞赛81920 | 新12288/24576是较低预算，末档残余截断需报告 |
| Nemotron | 卡片能力栏最大输出1M；vLLM客户端建议较大max_tokens，例如10000 | 能力上限和示例建议不同；不能把1M说成每次推理推荐值 |
| Coder | quickstart max_new_tokens512；默认context32768，可配置长上下文 | 512是示例，无独立的通用推荐输出长度；实验固定4096/16k |

配置偏离此前未显式记录的厂商预设是可核事实；但“高截断必然由配置引起”“需要262k才正常”不是已有证据。旧原件只有有限cap下未完成的比例，没有正确性标签，不证明无限不终止。

## 字段与核验链

`lcb_native_generation.py`保存固定模型/模式、7项采样、模板参数、模板和小配置文件哈希。由源码哈希覆盖，避免container只绑定/worker时读不到仓库data目录。`native_source_audit_sha256`绑定本次来源审计；`native_contract_sha256`绑定参数表。未知、缺失、非有限、布尔伪装数值、其他模型的effort、额外reasoning_budget/stop等覆盖一律拒绝。

Worker在构造LLM前核小文件，在ready中记录实际选中的模板哈希、模板参数和tokenizer EOS ID。每次先用厂商模板得到完整文本，再以add_special_tokens=false得到输入ID；握手记录：

- `rendered_prompt_sha256`与UTF-8字节数；不把原题或测试正文放进审计摘要。
- `input_ids_sha256`与实际长度；整个122题仍必须全部通过context guard。
- `native_template_sha256`及`chat_template_kwargs_sha256`，并记录native generation_settings。

逐候选再记录同样prompt摘要和 `sampling_parameters_submitted`，直接读取实际构造的SamplingParams对象字段，检查与配置完全相同。该名称有意保留“submitted”：引擎后续会补原生EOS，不能冒称它是引擎内部最终对象的完整转储。CPU测试使用fake engine；真实对象值和模板摘要仍要由新owner pilot验收。

Collector把完整generation_settings写入run，按参数和模板哈希核样本；导出器复核后写入cell及profile。实测分析入口要求新完整字段并拒绝旧协议或分层混用；没有改DID、博弈求解器、bootstrap或证书公式。合成fixture仍用于纯理论回归，不伪装成实测。

## 发布闸和下一包

当前 `require_current_execution` 对新准入/科学采集无条件报“等待cap-v3和owner-wrapper审查”，对旧协议报“仅历史复算”。即使手填所有审批true也不能启动。原lifecycle_acceptance技术路径保持，不代表需要重跑已关闭验收。

`lcb_admission.py --native`仅输出未批准参数草稿；所有嵌套reviewer/owner审批false，不提供prepare/执行入口。low草稿只是字段结构，不是已满足回退条件。2026-10-12已实现按原件重推的完整medium→low状态机及独立新封装，见 `experiments/calibration/admission-cap-path-v3.md` 与 `review/native-admission-v3-handoff.md`，当前待审且执行门仍关闭。旧两份Qwen结果不得接入新链。7200秒预案已撤销。

同一effort内两个cap必须保持完整tokenization与非阶段参数一致。medium切到low会原生改变输入文本/ID，跨effort只保持题和种子配对，不强行要求tokenization相同，也不把这种差别当成数据错误。H2按实际冻结的部署配置t写，π继续表示池化。90格、405N_main和GPU未知预算不变。
