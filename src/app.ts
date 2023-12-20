import express, { Request, Response } from "express";
import cookieparser from "cookie-parser";
import cors from "cors";
import userRouter from "./routes/user.router";

const app = express();

app.use(express.json());
app.use(cors());
app.use(cookieparser());
app.use("/api/v1/users", userRouter);
app.get("/", (req: Request, res: Response) => {
  res.send("hi");
});
export default app;
