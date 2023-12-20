class ApiResponse {
  statusCode: number;
  data: Record<string, any> | null;
  message: string;
  success: boolean;
  constructor(
    statusCode: number,
    data: Record<string, any> | null,
    message: string = "success"
  ) {
    this.statusCode = statusCode;
    this.data = data;
    this.message = message;
    this.success = statusCode < 400;
  }
}

export { ApiResponse };
