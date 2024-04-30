"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const UserRepository_1 = __importDefault(require("../repositories/UserRepository"));
const UserDto_1 = __importDefault(require("../Dto/UserDto"));
const secretKey = "claveSecretaSuperSegura"; // Clave secreta para firmar el JWT
let register = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, nombres, apellidos, telefono, password } = req.body;
        const salt = yield bcryptjs_1.default.genSalt(10);
        const hashedPassword = yield bcryptjs_1.default.hash(password, salt);
        const result = yield UserRepository_1.default.add(new UserDto_1.default(email, nombres, apellidos, telefono, hashedPassword));
        console.log(result);
        // Genera un token JWT con el email del usuario
        const token = jsonwebtoken_1.default.sign({ email }, secretKey, { expiresIn: "1h" });
        return res
            .status(201)
            .send({
            status: "register ok",
            password_hasheado: hashedPassword,
            token,
        });
    }
    catch (error) {
        if (error && error.code == "ER_DUP_ENTRY") {
            return res.status(500).send({ errorInfo: error.sqlMessage });
        }
    }
});
exports.default = register;
