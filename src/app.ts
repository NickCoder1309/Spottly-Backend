import express, { Request, Response } from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import userRoutes from "./routes/user";

dotenv.config();

const app = express();
if (!process.env.PORT) {
  process.exit(1);
}

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/api/users", userRoutes);

app.get("/", (_req: Request, res: Response) => {
  res.send("Backend API is running 🚀");
});

export default app;
