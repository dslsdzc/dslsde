"""dslsde — Web 模式共享状态

FastAPI 导入此模块获取已分析的 Model 实例。
main.py serve 注入，server.py 消费。
"""

from engine.model import Model

model: Model | None = None
