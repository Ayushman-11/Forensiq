from langgraph.graph import StateGraph, START, END
from app.agents.state import AgentState
from app.agents.context_agent import extract_context_node
from app.agents.ioc_agent import enrich_ioc_node
from app.agents.correlation_agent import correlate_events_node
from app.agents.mitre_agent import map_mitre_node
from app.agents.timeline_agent import build_timeline_node
from app.agents.risk_agent import assess_risk_node
from app.agents.recommendation_agent import generate_recommendations_node

def build_investigation_graph():
    """
    Builds and compiles the comprehensive LangGraph StateGraph for alert investigation.
    Pipeline sequence:
      START 
      -> extract_context 
      -> enrich_iocs 
      -> correlate_events 
      -> map_mitre 
      -> build_timeline 
      -> assess_risk 
      -> generate_recommendations 
      -> END
    """
    # 1. Initialize the state graph
    builder = StateGraph(AgentState)
    
    # 2. Add specialized agent nodes
    builder.add_node("extract_context", extract_context_node)
    builder.add_node("enrich_iocs", enrich_ioc_node)
    builder.add_node("correlate_events", correlate_events_node)
    builder.add_node("map_mitre", map_mitre_node)
    builder.add_node("build_timeline", build_timeline_node)
    builder.add_node("assess_risk", assess_risk_node)
    builder.add_node("generate_recommendations", generate_recommendations_node)
    
    # 3. Add edges sequentially
    builder.add_edge(START, "extract_context")
    builder.add_edge("extract_context", "enrich_iocs")
    builder.add_edge("enrich_iocs", "correlate_events")
    builder.add_edge("correlate_events", "map_mitre")
    builder.add_edge("map_mitre", "build_timeline")
    builder.add_edge("build_timeline", "assess_risk")
    builder.add_edge("assess_risk", "generate_recommendations")
    builder.add_edge("generate_recommendations", END)
    
    # 4. Compile the graph
    return builder.compile()

# Instantiate a global graph object
investigation_graph = build_investigation_graph()
