// tests/integration/user.login.test.ts
import request from "supertest";
import app from "../../src/app";
import * as userService from "../../src/services/user";
import bcrypt from "bcrypt";
import { generateToken } from "../../src/services/auth";

jest.mock("../../src/services/user");
jest.mock("bcrypt");
jest.mock("../../src/services/auth");

const mockGetUserByEmail = userService.getUserByEmail as jest.Mock;
const mockCompare = bcrypt.compare as jest.Mock;
const mockGenerateToken = generateToken as jest.Mock;

describe("POST /api/users/login", () => {
  beforeEach(() => jest.clearAllMocks());

  it("should login successfully", async () => {
    mockGetUserByEmail.mockResolvedValueOnce({
      id: "1",
      email: "test@example.com",
      username: "johnny",
      name: "John",
      password: "hashedpass",
    });
    mockCompare.mockResolvedValueOnce(true);
    mockGenerateToken.mockReturnValue("fake-token");

    const response = await request(app).post("/api/users/login").send({
      email: "test@example.com",
      password: "Password123",
    });

    expect(response.status).toBe(200);
    expect(response.body.token).toBe("fake-token");
    expect(response.body.user.email).toBe("test@example.com");
  });

  it("should return 400 if password incorrect", async () => {
    mockGetUserByEmail.mockResolvedValueOnce({
      id: "1",
      email: "test@example.com",
      username: "johnny",
      name: "John",
      password: "hashedpass",
    });
    mockCompare.mockResolvedValueOnce(false);

    const response = await request(app).post("/api/users/login").send({
      email: "test@example.com",
      password: "wrong",
    });

    expect(response.status).toBe(400);
    expect(response.body.error).toMatch(/incorrect password/i);
  });
});
