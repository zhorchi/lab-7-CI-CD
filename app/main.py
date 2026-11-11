from typing import ClassVar

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


class Item(BaseModel):
    _current_id: ClassVar[int] = 0

    id: int = Field(default_factory=lambda: Item._generate_id())
    name: str

    @classmethod
    def _generate_id(cls) -> int:
        cls._current_id += 1
        return cls._current_id


app = FastAPI()

items = [Item(name="Меч"), Item(name="Щит")]


@app.get("/")
def index():
    return {"message": "API работает"}


@app.get("/items")
def get_items():
    items_text = [item.model_dump() for item in items]
    return items_text


@app.get("/items/{item_id}")
def get_item(item_id: int):
    item = next((x for x in items if x.id == int(item_id)), None)
    if item:
        return item
    raise HTTPException(404, {"error": "Предмет не найден"})
