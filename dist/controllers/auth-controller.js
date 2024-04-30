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
const UserRepository_1 = __importDefault(require("../repositories/UserRepository"));
const bcrypt = require("bcryptjs");
let auth = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password } = req.body;
        const result = yield UserRepository_1.default.login(req.body);
        const rows = result[0];
        console.log(rows[0].password);
        if (rows.length > 0) {
            const isPasswordValid = yield bcrypt.compare(password, rows[0].password);
            console.log(isPasswordValid);
            if (!isPasswordValid) {
                return res.status(200).json({
                    status: 'Successful authentication', password: rows[0].password
                });
            }
        }
        return res.status(401).json({
            status: 'Incorrect username or password'
        });
    }
    catch (error) {
        console.log(error);
    }
});
exports.default = auth;
