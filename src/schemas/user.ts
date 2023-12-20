import { object, string } from "zod";
export const userRegistrationSchema = object({
  username: string(),
  email: string().email({ message: "Invalid email address" }),
  password: string()
    .min(8, { message: "Must be 8 or more characters long" })
    .max(15, { message: "Must be 15 characters long at max" })
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/,
      "Password is not strong enough. It must include at least one lowercase letter, one uppercase letter, one digit, and one special character."
    ),
  confirmpassword: string(),
})
  .required()
  .refine((data) => data.password === data.confirmpassword, {
    message: "Passwords don't match",
    path: ["confirmpassword"], // path of error
  });

export const userLoginSchema = object({
  username: string().optional(),
  email: string().email({ message: "Invalid email address" }).optional(),
  password: string()
    .min(8, { message: "Must be 8 or more characters long" })
    .max(15, { message: "Must be 15 characters long at max" })
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/,
      "Password is not strong enough. It must include at least one lowercase letter, one uppercase letter, one digit, and one special character."
    ),
})
  .required({
    password: true,
  })
  .refine((data) => data.username !== undefined || data.email !== undefined, {
    message: "Either username or email must be provided",
  });
