from fastapi import APIRouter, Depends
from app.adapters.scam_adapter import detect_scam
from app.adapters.agent_adapter import get_agent_reply
from app.adapters.intelligence_adapter import process_intelligence
from .schemas import MessageRequest, MessageResponse
from .auth import verify_api_key
from .session_manager import get_or_create_session, get_session, save_message_to_file


router = APIRouter()

@router.post("/message", response_model=MessageResponse)
def receive_message(
    data: MessageRequest,
    _: str = Depends(verify_api_key)
):
    session = get_or_create_session(data.sessionId)
    session["sessionId"] = data.sessionId

    session["messages"].append(data.message.dict())
    session["totalMessages"] += 1
    save_message_to_file(
        session["sessionId"],
        data.message.sender,
        data.message.text
    )
    
    

    detection = detect_scam(data.message.text, session)

    # Activate agent ONLY ONCE
    if detection.get("scamDetected") and not session["agentActive"]:
        session["scamDetected"] = True
        session["agentActive"] = True

    session["confidence"] = detection.get("confidence", 0.0)

    # 🤖 Reply logic
    if not session["agentActive"]:
        reply = "Okay, noted."
    else:
        reply = get_agent_reply(session, data.message.text)

    # 🧠 Intelligence (only after scam confirmed)
    if session["scamDetected"]:
        process_intelligence(session)

    return MessageResponse(
        status="success",
        reply=reply
    )

@router.get("/debug/intelligence/{session_id}")
def get_intelligence(session_id: str):
    session = get_session(session_id)
    return session.get("extractedIntelligence", {})
