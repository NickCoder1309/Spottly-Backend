import { supabase } from "../config/database";
import bcrypt from "bcryptjs";

export async function createUser(
  email: string,
  name: string,
  username: string,
  surname: string,
  age: number,
  password: string
) {
  const hashedPassword = await bcrypt.hash(password, 10);

  const { data, error } = await supabase
    .from("users")
    .insert([{ email, name, surname, username, age, password: hashedPassword }])
    .select();

  if (error) throw new Error(error.message);
  return data[0];
}

export async function getUserByEmail(email: string) {
  const { data, error } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .maybeSingle();
  if (error) throw new Error(error.message);
  return data; // could be null if not found
}

export async function getUserByUsername(username: string) {
  const { data, error } = await supabase
    .from("users")
    .select("*")
    .eq("username", username)
    .maybeSingle();
  if (error) throw new Error(error.message);
  return data; // could be null if not found
}
