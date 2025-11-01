import { supabase } from "../config/database";
import bcrypt from "bcrypt";

export async function createBusiness(
  email: string,
  name: string,
  busi_username: string,
  category: string,
  rating: number,
  description: string,
  address: string,
  password: string,
) {
  const hashedPassword = await bcrypt.hash(password, 10);

  const { data, error } = await supabase
    .from("businesses")
    .insert([
      {
        email,
        name,
        busi_username,
        category,
        rating,
        description,
        address,
        password: hashedPassword,
      },
    ])
    .select();

  if (error) throw new Error(error.message);
  return data[0];
}

export async function getBusinessByEmail(email: string) {
  const { data, error } = await supabase
    .from("businesses")
    .select("*")
    .eq("email", email)
    .maybeSingle();
  if (error) throw new Error(error.message);
  return data; // could be null if not found
}

export async function getBusinessByUsername(busi_username: string) {
  const { data, error } = await supabase
    .from("businesses")
    .select("*")
    .eq("busi_username", busi_username)
    .maybeSingle();
  if (error) throw new Error(error.message);
  return data; // could be null if not found
}
