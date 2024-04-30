import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import UserRepository from "../repositories/UserRepository";
import User from "../Dto/UserDto";
import { Request, Response } from "express";

const secretKey = "claveSecretaSuperSegura"; // Clave secreta para firmar el JWT

let register = async (req: Request, res: Response) => {
  try {
    const { email, nombres, apellidos, telefono, password } = req.body;

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const result = await UserRepository.add(
      new User(email, nombres, apellidos, telefono, hashedPassword)
    );
    console.log(result);

    // Genera un token JWT con el email del usuario
    const token = jwt.sign({ email }, secretKey, { expiresIn: "1h" });

    return res
      .status(201)
      .send({
        status: "register ok",
        password_hasheado: hashedPassword,
        token,
      });
  } catch (error: any) {
    if (error && error.code == "ER_DUP_ENTRY") {
      return res.status(500).send({ errorInfo: error.sqlMessage });
    }
  }
};

export default register;
