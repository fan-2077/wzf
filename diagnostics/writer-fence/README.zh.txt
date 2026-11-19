固定镜像写入者屏障权限诊断

运行入口：
python3 diagnostics/writer-fence/run_probe.py --output writer-fence-results

工作流always清理入口（复用同一输出目录）：
python3 diagnostics/writer-fence/run_probe.py --cleanup-only --output writer-fence-results

镜像固定为B0P_v1已经核验的GitLab摘要与image ID。脚本仅创建唯一命名、带本次所有权标签、无网络的独立容器；只在确认标签后清理该容器及其匿名卷。

探针使用未修改的实际gitlab-rails包装器。由于包装器会清除外部RUBYOPT，测试通过其真实chpst环境目录加载一个受控Bundler启动钩子，在Rails应用/数据库启动前记录实际UID/GID，调用与失败版本字节相同的B0进程和监督状态观察器。钩子不是Rails业务执行，不能据此宣称完整恢复已经通过。

容器不启动原GitLab应用。它使用真实runsv与Ruby建立两个最小puma/sidekiq进程夹具，检查服务活跃时root屏障拒绝、停止后root屏障放行，以及普通包装器降权后无法读取root监督进程时仍拒绝。测试只比较默认包装器与其原生NO_PRIVILEGE_DROP选项，完整保留每组进程扫描错误及原始监督状态。

若原始镜像尚未配置git账户或运行配置，夹具显式创建并在报告中记录。其UID数值属于该隔离夹具，不冒充先前完整实验的实际UID。包装器原始字节、摘要、执行输出、固定代码摘要、镜像身份与清理结果均进入产物。

判定范围：成功可证明该固定镜像的默认包装器降权会使现有扫描器失去root监督进程观察能力，且官方选项在夹具中修复该观察能力。它不能追溯证明上一场未保存的内部屏障值，也不能代替真实Rails运行、缓存/日志文件所有权和业务副作用的后续完整实验验收。
