import request from "supertest";
import app from "../../src/app";
import * as userService from "../../src/services/user";

jest.mock("../../src/services/user");
const mockGetUserByEmail = userService.getUserByEmail as jest.Mock;
const mockGetUserByUsername = userService.getUserByUsername as jest.Mock;
const mockCreateUser = userService.createUser as jest.Mock;

describe("POST /api/users/register", () => {
  beforeEach(() => jest.clearAllMocks());

  it("should register user successfully", async () => {
    mockGetUserByEmail.mockResolvedValueOnce(null);
    mockGetUserByUsername.mockResolvedValueOnce(null);
    mockCreateUser.mockResolvedValueOnce({
      id: "1",
      email: "test@example.com",
      username: "test",
      name: "John",
      age: 25,
    });

    const response = await request(app).post("/api/users/register").send({
      email: "test@example.com",
      name: "John",
      surname: "Doe",
      username: "test",
      age: 25,
      password: "Password123",
    });

    expect(response.status).toBe(201);
    expect(response.body.email).toBe("test@example.com");
  });
});
