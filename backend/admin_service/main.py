from fastapi import FastAPI

app = FastAPI(title="Admin Service")

users = [
    {"id": 1, "name": "Alice"},
    {"id": 2, "name": "Bob"},
]

app = FastAPI()

@app.get("/admin/users")
def get_all_users():
    return users

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int):
    global users

    users = [u for u in users if u["id"] != user_id]

    return {
        "message": f"user {user_id} deleted"
    }