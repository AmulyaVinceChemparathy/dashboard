from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from common.iris_db_engine import SessionLocal, engine, Base


# Create tables if not already present
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Test route - fetch all users
@app.get("/users")
def read_users(db: Session = Depends(get_db)):
    return db.query(User).all()

# Test route - add a user
@app.post("/users")
def create_user(name: str, email: str, db: Session = Depends(get_db)):
    user = User(name=name, email=email)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
