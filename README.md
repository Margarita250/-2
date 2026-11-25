// ===== TestingPlatform.Domain/Models/User.cs =====
using TestingPlatform.Domain.Enums;

namespace TestingPlatform.Domain.Models;

/// <summary>
/// Пользователь
/// </summary>
public class User
{
    /// <summary>
    /// Идентификатор пользователя
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Логин
    /// </summary>
    public string Login { get; set; }

    /// <summary>
    /// Хэш пароля
    /// </summary>
    public string PasswordHash { get; set; }

    /// <summary>
    /// Email
    /// </summary>
    public string Email { get; set; }

    /// <summary>
    /// Имя
    /// </summary>
    public string FirstName { get; set; }

    /// <summary>
    /// Отчество
    /// </summary>
    public string? MiddleName { get; set; }

    /// <summary>
    /// Фамилия
    /// </summary>
    public string LastName { get; set; }

    /// <summary>
    /// Роль (менеджер или студент)
    /// </summary>
    public UserRole Role { get; set; }

    /// <summary>
    /// Время создания
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Если роль студент - должна быть запись в таблице Student
    /// </summary>
    public Student? Student { get; set; }
}

// ===== TestingPlatform.Infrastructure/Repositories/UserRepository.cs (метод CreateAsync) =====
// Установить nuget-пакет BCrypt.Net-Next в проект TestingPlatform.Infrastructure

public async Task<int> CreateAsync(UserDto userDto)
{
    var user = mapper.Map<User>(userDto);
    user.FirstName = userDto.FirstName;
    user.LastName = userDto.LastName;
    user.MiddleName = userDto.MiddleName;
    user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(userDto.Password);
    await appDbContext.AddAsync(user);
    await appDbContext.SaveChangesAsync();
    return user.Id;
}

// ===== TestingPlatform.Application/Dtos/UserLoginDto.cs =====
namespace TestingPlatform.Application.Dtos;

public class UserLoginDto
{
    public string Login { get; set; }
    public string Password { get; set; }
}

// ===== TestingPlatform.Application/Interfaces/IAuthRepository.cs =====
using TestingPlatform.Application.Dtos;

namespace TestingPlatform.Application.Interfaces;

public interface IAuthRepository
{
    /// <summary>
    /// Аутентификация пользователя
    /// </summary>
    /// <param name="userLoginDto"></param>
    /// <returns></returns>
    Task<UserDto> AuthorizeUser(UserLoginDto userLoginDto);
}

// ===== TestingPlatform.Infrastructure/Repositories/AuthRepository.cs =====
using AutoMapper;
using Microsoft.EntityFrameworkCore;
using TestingPlatform.Application.Dtos;
using TestingPlatform.Application.Interfaces;
using TestingPlatform.Infrastructure.Exceptions;

namespace TestingPlatform.Infrastructure.Repositories;

public class AuthRepository(AppDbContext appDbContext, IMapper mapper) : IAuthRepository
{
    public async Task<UserDto> AuthorizeUser(UserLoginDto userLoginDto)
    {
        var user = await appDbContext.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Login == userLoginDto.Login);
        if (user == default)
            throw new EntityNotFoundException($"Пользователь {userLoginDto.Login} не найден.");
        if (!BCrypt.Net.BCrypt.Verify(userLoginDto.Password, user.PasswordHash))
            throw new ArgumentException("Введен неверный пароль.");
        return mapper.Map<UserDto>(user);
    }
}

// ===== Program.cs (регистрация репозитория) =====
builder.Services.AddScoped<IAuthRepository, AuthRepository>();

// ===== practice/Requests/Auth/AuthRequest.cs =====
using System.ComponentModel.DataAnnotations;

namespace practice.Requests.Auth;

public class AuthRequest
{
    [Required]
    public string Login { get; set; }

    [Required]
    public string Password { get; set; }
}

// ===== practice/Responses/Auth/AuthResponse.cs =====
using TestingPlatform.Domain.Enums;

namespace practice.Responses.Auth;

public class AuthResponse
{
    public int Id { get; set; }
    public string Login { get; set; }
    public string Password { get; set; }
    public string Email { get; set; }
    public string FirstName { get; set; }
    public string MiddleName { get; set; }
    public string LastName { get; set; }
    public UserRole Role { get; set; }
}

// ===== practice/Mappings/AuthProfile.cs =====
using AutoMapper;
using practice.Requests.Auth;
using practice.Responses.Auth;
using TestingPlatform.Application.Dtos;

namespace practice.Mappings;

public class AuthProfile : Profile
{
    public AuthProfile()
    {
        CreateMap<AuthRequest, UserLoginDto>();
        CreateMap<UserDto, AuthResponse>();
    }
}

// ===== practice/Controllers/AuthController.cs =====
using AutoMapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using practice.Requests.Auth;
using practice.Responses.Auth;
using TestingPlatform.Application.Dtos;
using TestingPlatform.Application.Interfaces;

namespace practice.Controllers;

[ApiController]
[Route("api/[controller]")]
[ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
public class AuthController(IAuthRepository authRepository, IMapper mapper) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Authorize([FromBody] AuthRequest auth)
    {
        var userLoginDto = mapper.Map<UserLoginDto>(auth);
        var user = await authRepository.AuthorizeUser(userLoginDto);
        var response = mapper.Map<AuthResponse>(user);
        return Ok(response);
    }
}
