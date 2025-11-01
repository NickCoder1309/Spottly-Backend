import { Router } from "express";
import { registerUser, loginUser, updateAUser } from "../controller/user";

const router = Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.put("/updateUser/:userId", updateAUser);

export default router;
