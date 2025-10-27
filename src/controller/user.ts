import bcrypt from "bcrypt";
import {
  createUser,
  getUserByEmail,
  getUserByUsername
} from "../services/user";
import { generateToken } from "../services/auth";
import { Request, Response } from "express";

export async function registerUser(req: Request, res: Response) {
  try {
    const { email, name, age, password, username, surname } = req.body;

    if (!email || !name || age === undefined || !password) {
      return res.status(400).json({
        error: "Faltan campos obligatorios: name, email, age, password"
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (typeof email !== "string" || !emailRegex.test(email)) {
      return res.status(400).json({ error: "Email inválido" });
    }

    if (typeof name !== "string" || name.trim().length === 0) {
      return res.status(400).json({ error: "Nombre inválido" });
    }

    const ageNum = Number(age);
    if (Number.isNaN(ageNum) || ageNum < 0 || ageNum > 120) {
      return res.status(400).json({ error: "Edad inválida" });
    }

    const passwordStr =
      typeof password === "string"
        ? password
        : typeof password === "number"
        ? String(password)
        : null;

    if (!passwordStr || passwordStr.length < 8) {
      return res
        .status(400)
        .json({ error: "La contraseña debe tener al menos 8 caracteres" });
    }

    const forbiddenPatterns = [
      /(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b)/i, // SQL keywords
      /(\bUNION\b|\bOR\b.*=.*\b|\bAND\b.*=.*\b)/i, // SQL injection patterns
      /['"`;\\]/g,
      /^\s+$/
    ];

    const hasForbiddenPattern = forbiddenPatterns.some(pattern =>
      pattern.test(passwordStr)
    );
    if (hasForbiddenPattern) {
      return res.status(400).json({
        error: "La contraseña contiene caracteres o patrones no permitidos"
      });
    }

    if (!/(?=.*[a-zA-Z])(?=.*\d)/.test(passwordStr)) {
      return res.status(400).json({
        error: "La contraseña debe contener al menos una letra y un número"
      });
    }
    const existingEmail = await getUserByEmail(email);
    const existingUsername = await getUserByUsername(username);
    if (existingEmail || existingUsername) {
      return res
        .status(409)
        .json({ error: "El email o nombre de usuario ya está registrado" });
    }

    const created = await createUser(
      email,
      name,
      passwordStr,
      surname,
      ageNum,
      username
    );
    const safeUser = created
      ? {
          id: created.id,
          email: created.email,
          username: created.username,
          name: created.name,
          age: created.age
        }
      : null;
    return res.status(201).json(safeUser);
  } catch {
    return res.status(500).json({ error: "Server error" });
  }
}

export async function loginUser(req: Request, res: Response) {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Missing parameters for login" });

    const user = await getUserByEmail(email);
    if (!user) return res.status(404).json({ error: "User not found" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(400).json({ error: "Incorrect password" });
    const token = generateToken({
      id: user.id,
      email: user.email,
      username: user.username
    });

    return res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        name: user.name,
        surname: user.surname,
        age: user.age
      }
    });
  } catch {
    return res.status(500).json({ error: "Server error" });
  }
}
