from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List
from datetime import datetime, timedelta
from jose import JWTError, jwt
import mysql.connector

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Configuración para JWT
SECRET_KEY = "tojizenin"  # Reemplaza con una clave segura
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Modelos Pydantic para Usuario
class UserBase(BaseModel):
    name: str
    email: str

class User(UserBase):
    id: int

    class Config:
        orm_mode = True

# Conexión a la base de datos MySQL
def get_db():
    connection = mysql.connector.connect(
        host="examen.c0h0a4oemuya.us-east-1.rds.amazonaws.com",      # Ejemplo: mydb.xxx.us-east-1.rds.amazonaws.com
        user="admin",
        password="gojo1818",
        database="examen"
    )
    return connection

# Función para crear el token de acceso
def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Endpoints de autenticación ---

@app.post("/login")
async def login(user: UserBase):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    # Buscar el usuario por email en la base de datos
    cursor.execute("SELECT * FROM users WHERE email = %s", (user.email,))
    db_user = cursor.fetchone()
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    # Se podría agregar verificación de contraseña aquí si se implementa
    token = create_access_token(data={"sub": db_user['email']})
    return {"token": token}

# --- Endpoints CRUD para Usuarios ---

# 1. Obtener lista de usuarios (GET /users)
@app.get("/users", response_model=List[User])
async def get_users(token: str = Depends(oauth2_scheme)):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    return users

# 2. Obtener usuario en particular (GET /users/{user_id})
@app.get("/users/{user_id}", response_model=User)
async def get_user(user_id: int, token: str = Depends(oauth2_scheme)):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# 3. Crear un usuario (POST /users)
@app.post("/users", response_model=User)
async def create_user(user: UserBase, token: str = Depends(oauth2_scheme)):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO users (name, email) VALUES (%s, %s)",
        (user.name, user.email)
    )
    db.commit()
    # Obtenemos el id autogenerado para el usuario creado
    cursor.execute("SELECT LAST_INSERT_ID()")
    user_id = cursor.fetchone()[0]
    return {**user.dict(), "id": user_id}

# 4. Actualizar un usuario (PUT /users/{user_id})
@app.put("/users/{user_id}", response_model=User)
async def update_user(user_id: int, user: UserBase, token: str = Depends(oauth2_scheme)):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE users SET name = %s, email = %s WHERE id = %s",
        (user.name, user.email, user_id)
    )
    db.commit()
    # Verificamos que el usuario haya sido actualizado
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    updated_user = cursor.fetchone()
    if updated_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return updated_user

# 5. Eliminar un usuario (DELETE /users/{user_id})
@app.delete("/users/{user_id}")
async def delete_user(user_id: int, token: str = Depends(oauth2_scheme)):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    db.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}
