from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List
from datetime import datetime, timedelta
from jose import JWTError, jwt
import mysql.connector
from passlib.context import CryptContext  # Para hash de contraseñas

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Configuración para JWT
SECRET_KEY = "tojizenin"  # Reemplaza con una clave segura
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configuración para el manejo de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Modelos Pydantic para Usuario
class UserBase(BaseModel):
    name: str
    email: str
    password: str  # Ahora la contraseña se incluye en el modelo base

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

# Función para verificar la contraseña (usando hashing)
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Función para hashear la contraseña
def get_password_hash(password):
    return pwd_context.hash(password)

# --- Endpoints de autenticación ---

@app.post("/login")
async def login(user: UserBase):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    # Buscar el usuario por email en la base de datos
    cursor.execute("SELECT * FROM users WHERE email = %s", (user.email,))
    db_user = cursor.fetchone()
    if not db_user or not verify_password(user.password, db_user['password']):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    # Generar el token JWT
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
    hashed_password = get_password_hash(user.password)  # Hasheamos la contraseña
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
        (user.name, user.email, hashed_password)
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
    hashed_password = get_password_hash(user.password)  # Hasheamos la contraseña
    cursor.execute(
        "UPDATE users SET name = %s, email = %s, password = %s WHERE id = %s",
        (user.name, user.email, hashed_password, user_id)
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
