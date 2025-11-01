import { registerBusiness } from "../../src/controller/business";
import * as businessService from "../../src/services/business";
import { Request, Response } from "express";

jest.mock("../../src/services/business");

const mockGetBusinessByEmail = businessService.getBusinessByEmail as jest.Mock;
const mockGetBusinessByUsername =
  businessService.getBusinessByUsername as jest.Mock;
const mockCreateBusiness = businessService.createBusiness as jest.Mock;

describe("registerBusiness (Unit)", () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let statusMock: jest.Mock;
  let jsonMock: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    statusMock = jest.fn().mockReturnThis();
    jsonMock = jest.fn();
    res = {
      status: statusMock,
      json: jsonMock,
    };
  });

  it("should return 400 if required fields are missing", async () => {
    req = { body: { email: "test@example.com" } };

    await registerBusiness(req as Request, res as Response);

    expect(statusMock).toHaveBeenCalledWith(400);
    expect(jsonMock).toHaveBeenCalledWith(
      expect.objectContaining({
        error: expect.stringContaining("Faltan datos necesarios"),
      }),
    );
  });

  it("should return 400 for invalid email", async () => {
    req = {
      body: {
        email: "invalidemail",
        name: "Test",
        busi_username: "biz",
        category: "food",
        password: "Password1",
      },
    };

    await registerBusiness(req as Request, res as Response);

    expect(statusMock).toHaveBeenCalledWith(400);
    expect(jsonMock).toHaveBeenCalledWith({ error: "Email inválido" });
  });

  it("should return 400 if password is too short", async () => {
    req = {
      body: {
        email: "test@example.com",
        name: "Biz",
        busi_username: "testbiz",
        category: "food",
        password: "123",
      },
    };

    await registerBusiness(req as Request, res as Response);

    expect(statusMock).toHaveBeenCalledWith(400);
    expect(jsonMock).toHaveBeenCalledWith({
      error: "La contraseña debe tener al menos 8 caracteres",
    });
  });

  it("should return 400 if password lacks letters or numbers", async () => {
    req = {
      body: {
        email: "test@example.com",
        name: "Biz",
        busi_username: "testbiz",
        category: "food",
        password: "onlyletters",
      },
    };

    await registerBusiness(req as Request, res as Response);

    expect(statusMock).toHaveBeenCalledWith(400);
    expect(jsonMock).toHaveBeenCalledWith({
      error: "La contraseña debe contener al menos una letra y un número",
    });
  });

  it("should return 409 if email or username already exist", async () => {
    mockGetBusinessByEmail.mockResolvedValueOnce({ id: 1 });
    mockGetBusinessByUsername.mockResolvedValueOnce(null);

    req = {
      body: {
        email: "duplicate@example.com",
        name: "Biz",
        busi_username: "testbiz",
        category: "food",
        password: "Password1",
      },
    };

    await registerBusiness(req as Request, res as Response);

    expect(mockGetBusinessByEmail).toHaveBeenCalledWith(
      "duplicate@example.com",
    );
    expect(statusMock).toHaveBeenCalledWith(409);
    expect(jsonMock).toHaveBeenCalledWith({
      error: "El email o nombre de usuario ya está registrado",
    });
  });

  it("should return 201 when business is successfully created", async () => {
    mockGetBusinessByEmail.mockResolvedValueOnce(null);
    mockGetBusinessByUsername.mockResolvedValueOnce(null);
    mockCreateBusiness.mockResolvedValueOnce({
      id: "biz123",
      name: "My Business",
      busi_username: "biz",
      email: "test@example.com",
      category: "food",
      description: "desc",
      address: "addr",
    });

    req = {
      body: {
        email: "test@example.com",
        name: "My Business",
        busi_username: "biz",
        category: "food",
        rating: 5,
        description: "desc",
        address: "addr",
        password: "Password1",
      },
    };

    await registerBusiness(req as Request, res as Response);

    expect(mockCreateBusiness).toHaveBeenCalled();
    expect(statusMock).toHaveBeenCalledWith(201);
    expect(jsonMock).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "biz123",
        name: "My Business",
        email: "test@example.com",
      }),
    );
  });

  it("should return 500 if an error is thrown", async () => {
    mockGetBusinessByEmail.mockRejectedValueOnce(new Error("Database error"));

    req = {
      body: {
        email: "error@example.com",
        name: "Biz",
        busi_username: "biz",
        category: "food",
        password: "Password1",
      },
    };

    await registerBusiness(req as Request, res as Response);

    expect(statusMock).toHaveBeenCalledWith(500);
    expect(jsonMock).toHaveBeenCalledWith({ error: "Database error" });
  });
});
