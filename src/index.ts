import app from "./app";
import connectDb from "./db";
import dotenv from "dotenv";
import path from "path";
const envPath = path.resolve(__dirname, "../.env");

dotenv.config({
  path: envPath,
});

connectDb().then(() => {
  app.listen(process.env.PORT || 4000, () => {
    console.log(`app running on port ${process.env.PORT}`);
  });
});
