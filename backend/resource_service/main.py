from fastapi import FastAPI

app = FastAPI(title="Resource Service")

resources = [
    {"id": 1, "name": "Document A"},
    {"id": 2, "name": "Document B"},
]

@app.get("/resources")
def get_resources():
    return resources

@app.post("/resources")
def create_resource(resource: dict):
    resources.append(resource)
    return {
        "message": "created",
        "resource": resource
    }