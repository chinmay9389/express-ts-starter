import jwt, { Secret, JwtPayload } from "jsonwebtoken";
import { User } from "../models/user.model";
import { asyncHandler } from "../utils/asyncHandler";
import { ApiError } from "../utils/apiError";
import { Request } from "express";
import { getErrorMessage } from "../utils/utils";

export const verifyUser = asyncHandler(async (req: Request, res, next) => {
  try {
    const token =
      req.cookies?.accessToken ||
      req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      throw new ApiError(401, "Unauthorized request");
    }
    const decodedToken = jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET as Secret
    ) as JwtPayload;

    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken"
    );
    if (!user) {
      throw new ApiError(401, "Invalid Access Token");
    }
    console.log(user);
    console.log(typeof user);
    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(401, getErrorMessage(error) || "Invalid access token");
  }
});
