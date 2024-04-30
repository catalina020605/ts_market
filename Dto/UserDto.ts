class User {
    email: string;
    nombres: string;
    apellidos: string;
    telefono: string;
    password: string
    constructor(
        email: string, nombres: string,
        apellidos: string, telefono: string,
        password: string
    ) {
        this.email = email;
        this.nombres = nombres;
        this.apellidos = apellidos;
        this.telefono = telefono;
        this.password = password
    }
}

export default User;