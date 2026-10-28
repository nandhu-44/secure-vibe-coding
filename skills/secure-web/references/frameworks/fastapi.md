# FastAPI secure baseline

```python
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import select

app = FastAPI(docs_url=None if settings.env == "prod" else "/docs", openapi_url=None if settings.env == "prod" else "/openapi.json")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_credentials=True,
                   allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"])

class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")          # reject unknown fields (mass assignment)
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(max_length=10_000)

class NoteOut(BaseModel):
    id: int
    title: str
    body: str

async def current_user(request: Request) -> User:
    user = await auth_backend.authenticate(request)    # verified JWT/session; never a header the client controls
    if user is None:
        raise HTTPException(401)
    return user

CurrentUser = Annotated[User, Depends(current_user)]

@app.get("/notes/{note_id}", response_model=NoteOut)   # response_model filters output fields
async def get_note(note_id: int, user: CurrentUser, db: DB):
    note = await db.scalar(select(Note).where(Note.id == note_id, Note.owner_id == user.id))
    if note is None:
        raise HTTPException(404)
    return note

@app.post("/notes", response_model=NoteOut, status_code=201)
async def create_note(data: NoteIn, user: CurrentUser, db: DB):
    note = Note(**data.model_dump(), owner_id=user.id)  # owner from session, not body
    db.add(note); await db.commit()
    return note
```

## Pitfalls
- Use `response_model` or explicit output schemas. Returning ORM objects with `from_attributes` can leak fields unless filtered.
- JWT with `PyJWT`: `jwt.decode(token, key, algorithms=["HS256"], audience=..., issuer=...)`. Avoid `python-jose` for new code (unmaintained, past alg confusion bugs).
- SQLAlchemy `text()` takes bound params: `text("... WHERE id = :id").bindparams(id=x)`. Never use f-strings.
- Background tasks and websockets need their own auth checks.
- Rate limiting: slowapi (see rate-limiting.md). Body size: enforce at the proxy.
- File uploads: `UploadFile`. Check the size while streaming, verify magic bytes, store with a uuid name.
