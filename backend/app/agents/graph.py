from langgraph.graph import StateGraph, START, END
from app.agents.state import AgentState
from app.agents.context_agent import extract_context_node
from app.agents.ioc_agent import enrich_ioc_node

def build_investigation_graph():
    """
    Builds and compiles the LangGraph StateGraph for alert investigation.
    """
    # 1. Initialize the state graph
    builder = StateGraph(AgentState)
    
    # 2. Add nodes
    builder.add_node("extract_context", extract_context_node)
    builder.add_node("enrich_iocs", enrich_ioc_node)
    
    # 3. Add edges
    builder.add_edge(START, "extract_context")
    builder.add_edge("extract_context", "enrich_iocs")
    builder.add_edge("enrich_iocs", END)
    
    # 4. Compile the graph
    return builder.compile()

# Instantiate a global graph object
investigation_graph = build_investigation_graph()
