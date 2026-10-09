"""Local Hugging Face chat model behind the application's provider interface.

Used when neither Ollama nor an API key is available. Runs in fp16 on a CUDA GPU
when one is present, otherwise in fp32 on the CPU. Decoding is greedy when
temperature is 0, so explanations are reproducible on the same hardware.
"""

from __future__ import annotations

from typing import Optional

import torch

from app.llm.providers.base import BaseLLMProvider


class HuggingFaceProvider(BaseLLMProvider):
    def __init__(self, model: str = "Qwen/Qwen2.5-1.5B-Instruct") -> None:
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.model_name = model
        self._tok = AutoTokenizer.from_pretrained(model)
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        dtype = torch.float16 if self.device == "cuda" else torch.float32
        self._model = AutoModelForCausalLM.from_pretrained(model, torch_dtype=dtype).to(self.device)
        self._model.eval()

    @property
    def name(self) -> str:
        return f"huggingface:{self.model_name}"

    async def complete(self, prompt: str, system: Optional[str] = None,
                       temperature: float = 0.3, max_tokens: int = 512) -> str:
        messages = ([{"role": "system", "content": system}] if system else []) + [
            {"role": "user", "content": prompt}]
        ids = self._tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt").to(self.device)
        sampling = {"do_sample": True, "temperature": temperature} if temperature > 0 else {"do_sample": False}
        with torch.no_grad():
            out = self._model.generate(ids, max_new_tokens=max_tokens, pad_token_id=self._tok.eos_token_id,
                                       **sampling)
        return self._tok.decode(out[0, ids.shape[1]:], skip_special_tokens=True).strip()

    async def health_check(self) -> bool:
        return True
