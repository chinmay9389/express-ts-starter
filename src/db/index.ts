import mongoose from "mongoose";

const connectDb = async () => {
  try {
    const mongourl = process.env.mongourl || "";
    const connectionInstance = await mongoose.connect(mongourl);
    console.log(
      `\nMongoDB connected !! DB HOST: ${connectionInstance.connection.host}`
    );
  } catch (error) {
    console.log("Mongo failed to connect", error);
    process.exit(1);
  }
};

export default connectDb;
