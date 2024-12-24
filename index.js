// Dependencias
import express from "express";
import pkg from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
const { Pool } = pkg;
const app = express();
const port = 3000;

// Config PostgreSQL
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "softjobs",
  password: "",
  port: 5432,
});
/////////////////////////////////////////////

// Middleware
app.use(express.json());

// Middleware - reportar consultas en el servidor
app.use((request, response, next) => {
  console.log(`Ruta consultada: ${request.method} ${request.path}`);
  next();
});

// Fx para manejar errores
// Capturar y devolver posibles errores en el servidor
const handleErrors = (fn) => async (request, response, nextfn) => {
  try {
    await fn(request, response, nextfn);
  } catch (error) {
    console.error(error);
    response
      .status(500)
      .json({ error: "Error interno del servidor", detalle: error.message });
  }
};

// Firmar, verificar y decodificar tokens JWT
const verificarToken = (token) => {
  try {
    return jwt.verify(token, "clave_secreta");
  } catch (error) {
    return null;
  }
};

// Rutas
// Registrar usuarios en la base de datos y encriptar las contraseñas
app.post(
  "/usuarios",
  handleErrors(async (req, res) => {
    const { email, password, rol, lenguage } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email es requerido" });
    } else if (!password) {
      return res.status(400).json({ error: "Contraseña es requerida" });
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      const query =
        "INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *";
      const values = [email, hashedPassword, rol, lenguage];

      const { rows } = await pool.query(query, values);
      res.status(201).json(rows[0]);
    }
  })
);
// Rutas
// Iniciar sesión. Firmar tokens JWT Y verificar la existencia de credenciales en la ruta correspondiente
app.post(
  "/login",
  handleErrors(async (req, res) => {
    const { email, password } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email es requerido" });
    } else if (!password) {
      return res.status(400).json({ error: "Contraseña es requerida" });
    } else {
      const query = "SELECT * FROM usuarios WHERE email = $1";
      const { rows } = await pool.query(query, [email]);

      if (rows.length === 0) {
        return res.status(404).json({ error: "Usuario no encontrado" });
      } else {
        const usuario = rows[0];
        const validPassword = await bcrypt.compare(password, usuario.password);

        if (!validPassword) {
          return res.status(403).json({ error: "Contraseña incorrecta" });
        } else {
          const token = jwt.sign({ email: usuario.email }, "clave_secreta", {
            expiresIn: "1h",
          });
          res.json({ token });
        }
      }
    }
  })
);

// Rutas
// Obtener usuarios de la base de datos. Validar el token recibido en la ruta que corresponda
app.get(
  "/usuarios",
  handleErrors(async (req, res) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Token no proporcionado" });
    }

    const decoded = verificarToken(token);

    if (!decoded) {
      return res.status(403).json({ error: "Token inválido" });
    }

    const query = "SELECT * FROM usuarios WHERE email = $1";
    const { rows } = await pool.query(query, [decoded.email]);

    if (rows.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json(rows[0]);
  })
);

/////////////
// Manejo de rutas no encontradas
app.use((req, res) => res.status(404).json({ error: "Ruta no encontrada" }));

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
