using NSE.WebApp.MVC.Configurations;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdentityConfiguration();
builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseMvcConfiguration();

app.Run();
