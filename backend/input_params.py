from pydantic import BaseModel

class credentials(BaseModel):
    username:str 
    email:str
    password:str

