import UserRepository from '../repositories/UserRepository';
const bcrypt = require("bcryptjs");
import { Request, Response } from "express";


let auth = async (req: Request, res: Response) => {
      try {
        const {email, password} = req.body;
        const result:any = await UserRepository.login(req.body);
        const rows = result[0];
      console.log(rows[0].password);
      
        
         if (rows.length > 0){
           const isPasswordValid = await bcrypt.compare(password, rows[0].password);
           console.log(isPasswordValid);
           
           if (!isPasswordValid){
            return res.status(200).json({ 
               status: 'Successful authentication',password: rows[0].password
             });
           }
         }
        return res.status(401).json({ 
          status: 'Incorrect username or password'
        });
      } catch (error) {
        console.log(error);
      }
}


export default auth;