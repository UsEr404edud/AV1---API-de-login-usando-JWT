require("dotenv").config()
const express = require("express")
const cors = require("cors")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const db = require("./db")

const app = express()
const port = process.env.PORT || 3000
app.use(express.json())
app.use(cors())

// Middleware de autenticação (Authorization: Bearer <token>)
function autenticar(req, res, next) {
    const authHeader = req.headers["authorization"]
    const token = authHeader && authHeader.split(" ")[1]
    if (token == null) {
        return res.status(401).json({ erro: "Token não enviado, usar Authorization Bearer <token>" })
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, usuario) => {
        if (err) return res.status(403).json({ erro: "Token inválido ou expirado" })
        req.usuario = usuario
        next()
    })
}

// Cadastro de cliente
app.post("/cliente", async (req, res) => {
    try {
        const { nome, cpf, celular, email, senha } = req.body
        if (!nome || !cpf || !celular || !email || !senha) {
            return res.status(400).json({ msg: "Preencha todos os campos!" })
        }
        const senhaCript = await bcrypt.hash(senha, 10)
        const resultado = await db.pool.query(
            `INSERT INTO cliente (nome, cpf, celular, email, senha)
             VALUES (?, ?, ?, ?, ?)`,
            [nome, cpf, celular, email, senhaCript]
        )
        res.status(201).json({ msg: "Cliente cadastrado, ID = " + resultado[0].insertId })
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ msg: "CPF ou email já cadastrado!" })
        }
        res.status(500).json({ erro: error.message })
    }
})

// Login: retorna nome e token JWT
app.post("/login", async (req, res) => {
    try {
        const user = req.body
        if (!user.email || !user.senha) {
            return res.status(400).json({ msg: "Informe email e senha!" })
        }
        const resultado = await db.pool.query(
            "SELECT id, nome, email, senha FROM cliente WHERE email = ?", [user.email]
        )
        const dados_bd = resultado[0][0]
        if (!dados_bd) {
            return res.status(401).json({ msg: "Credenciais inválidas!" })
        }
        const senha_valida = await bcrypt.compare(user.senha, dados_bd.senha)
        if (!senha_valida) {
            return res.status(401).json({ msg: "Credenciais inválidas!" })
        }
        const payload = { id: dados_bd.id, email: dados_bd.email }
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "2h" })
        return res.status(200).json({ nome: dados_bd.nome, token: token })
    } catch (error) {
        res.status(500).json({ erro: error.message })
    }
})

// Perfil do cliente logado (rota protegida)
app.get("/cliente/perfil", autenticar, async (req, res) => {
    try {
        const result = await db.pool.query("SELECT * FROM cliente WHERE id = ?", [req.usuario.id])
        const perfil = result[0][0]
        if (!perfil) return res.status(404).json({ erro: "Cliente não encontrado" })
        delete perfil.senha
        res.status(200).json(perfil)
    } catch (err) {
        res.status(500).json({ erro: "Erro interno" })
    }
})

app.listen(port, () => {
    console.log("API rodando na porta " + port)
})
