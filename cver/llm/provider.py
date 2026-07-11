from __future__ import annotations
import json, os, urllib.request
from dataclasses import dataclass
from typing import Any

@dataclass
class LLMResponse:
    text: str
    json_obj: dict[str,Any]
    provider: str
    cost_estimate: float = 0.0

class MockLLMProvider:
    name="mock"
    def complete_json(self, system: str, prompt: str, schema_hint: dict | None=None) -> LLMResponse:
        obj={"mode":"mock","summary":"Mock LLM response; rules remain authoritative.","confidence":0.5,"human_confirm_required":True}
        return LLMResponse(json.dumps(obj,ensure_ascii=False), obj, self.name, 0.0)

class RuleLLMProvider(MockLLMProvider):
    name="rule"

class OpenAICompatibleProvider(MockLLMProvider):
    name="openai-compatible"
    def complete_json(self, system: str, prompt: str, schema_hint: dict | None=None) -> LLMResponse:
        base=os.environ.get("CVER_OPENAI_COMPATIBLE_BASE_URL","").rstrip("/")
        key=os.environ.get("CVER_OPENAI_COMPATIBLE_API_KEY","")
        model=os.environ.get("CVER_OPENAI_COMPATIBLE_MODEL","gpt-4o-mini")
        if not base or not key:
            return super().complete_json(system,prompt,schema_hint)
        body=json.dumps({"model":model,"messages":[{"role":"system","content":system},{"role":"user","content":prompt}],"response_format":{"type":"json_object"}}).encode()
        req=urllib.request.Request(base+"/chat/completions",data=body,method="POST",headers={"Content-Type":"application/json","Authorization":f"Bearer {key}"})
        try:
            with urllib.request.urlopen(req,timeout=60) as resp:
                data=json.loads(resp.read().decode())
            text=data.get("choices",[{}])[0].get("message",{}).get("content","{}")
            try: obj=json.loads(text)
            except Exception: obj={"raw":text}
            return LLMResponse(text,obj,self.name,0.0)
        except Exception as e:
            return LLMResponse(json.dumps({"error":str(e),"fallback":"mock"}),{"error":str(e),"fallback":"mock"},self.name,0.0)

def provider_from_config(cfg: dict) -> MockLLMProvider:
    name=cfg.get("llm",{}).get("provider","mock")
    if name=="openai-compatible": return OpenAICompatibleProvider()
    if name=="rule": return RuleLLMProvider()
    return MockLLMProvider()
