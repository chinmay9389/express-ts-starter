import { User, IUser } from "../models/user.model";
import { ApiError } from "../utils/apiError";
import { ApiResponse } from "../utils/apiResponse";
import { asyncHandler } from "../utils/asyncHandler";
import jwt, { Secret, JwtPayload } from "jsonwebtoken";
import { getErrorMessage } from "../utils/utils";
import { userLoginSchema, userRegistrationSchema } from "../schemas/user";
import { ZodError } from "zod";

const generateTokens = async (userId: string) => {
  try {
    const user = await User.findById(userId);
    if (user) {
      const accessToken = user?.generateAccessToken();
      const refreshToken = user?.generateRefreshToken();
      user.refreshToken = refreshToken;
      await user.save({ validateBeforeSave: false });
      return { accessToken, refreshToken };
    }
    return { accessToken: "", refreshToken: "" };
  } catch (error) {
    throw new ApiError(500, "Error generating tokens");
  }
};

const registercontroller = asyncHandler(async (req, res) => {
  try {
    const userData = userRegistrationSchema.parse(req.body);
    const { username, email, password, confirmpassword } = userData;
    console.log(username, email, password);
    const existingUser = await User.findOne({
      $or: [{ username }, { email }],
    });
    if (existingUser) {
      throw new ApiError(
        409,
        "User already registered with same username or email"
      );
    }
    const user: IUser = await User.create({
      username: username.toLowerCase(),
      email: email,
      password: password,
    });
    const createdUser = await User.findById(user._id).select(
      "-password -refreshToken"
    );
    if (!user) {
      throw new ApiError(500, "Something went wrong while creating user");
    }
    return res
      .status(200)
      .json(new ApiResponse(200, createdUser, "User created successfully"));
  } catch (error) {
    if (error instanceof ZodError) {
      res.status(400).send(error.errors);
    }
  }
});

const logincontroller = asyncHandler(async (req, res) => {
  try {
    const userData = userLoginSchema.parse(req.body);
    const { username, email, password } = userData;
    if (!username && !email) {
      throw new ApiError(400, "username or email is required");
    }
    const user: IUser | null = await User.findOne({
      $or: [{ username }, { email }],
    });
    if (!user) {
      throw new ApiError(404, "User doesn't exist");
    }
    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) {
      throw new ApiError(401, "Invalid user credentials");
    }

    const { accessToken, refreshToken } = await generateTokens(user._id);

    const loggedInUser = await User.findById(user._id).select(
      "-password -refreshToken"
    );

    const options = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(
        new ApiResponse(
          200,
          { user: loggedInUser, accessToken, refreshToken },
          "User logged in successfully"
        )
      );
  } catch (error) {
    if (error instanceof ZodError) {
      res.status(400).send(error.errors);
    }
  }
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingToken = req.cookies.refreshToken || req.body.refreshToken;
  if (!incomingToken) {
    throw new ApiError(401, "unauthorized request");
  }
  try {
    const decodedToken = jwt.verify(
      incomingToken,
      process.env.REFRESH_TOKEN_SECRET as Secret
    ) as JwtPayload;
    const user = await User.findById(decodedToken?._id);
    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }
    if (incomingToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }
    const options = {
      httpOnly: true,
      secure: true,
    };
    const { accessToken, refreshToken } = await generateTokens(user._id);
    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: refreshToken },
          "Access token refreshed"
        )
      );
  } catch (error) {
    throw new ApiError(401, getErrorMessage(error) || "Invalid refresh token");
  }
});

const logoutController = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      new: true,
    }
  );
  const options = {
    httpOnly: true,
    secure: true,
  };
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out"));
});

export {
  registercontroller,
  logincontroller,
  refreshAccessToken,
  logoutController,
};
