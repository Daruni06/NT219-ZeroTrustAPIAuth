from fastapi import FastAPI, Header

app = FastAPI(title="User Service")

users = [
    {"id": 1, "name": "Alice"},
    {"id": 2, "name": "Bob"},
]

@app.get("/users")
def get_users(x_user_id: str | None = Header(default=None)):
    return {
        "caller": x_user_id,
        "users": users
    }

@app.get("/users/{user_id}")
def get_user(user_id: int):
    for user in users:
        if user["id"] == user_id:
            return user

    return {"error": "User not found"}