<?php
require 'includes/header.php'
?>

<main>
<link rel="stylesheet" href="css/login.css">
        <div class = "bg-cover">
            <div class = "row">
                <div id="slides" class="carousel slide col-md-8 offset-md-2" data-ride="carousel" style = "margin-top: 20px;">
                  <ol class="carousel-indicators">
                    <li data-target="#slides" data-slide-to="0" class="active"></li>
                    <li data-target="#slides" data-slide-to="1" ></li>
                    <li data-target="#slides" data-slide-to="2"></li>
                  </ol>
                  <div class="carousel-inner">
                    <div class="carousel-item active">
                      <img class="d-block mx-auto" src="images/Carousel-Minari.jpg" alt="First slide">
                    </div>
                    <div class="carousel-item">
                      <img class="d-block mx-auto" src="images/Carousel-Nomadland.jpg" alt="Second slide">
                    </div>
                    <div class="carousel-item">
                      <img class="d-block mx-auto" src="images/Carousel-1917.jpg" alt="Third slide">
                    </div>
                  </div>
                  <a class="carousel-control-prev" href="#slides" role="button" data-slide="prev">
                    <span class="carousel-control-prev-icon" aria-hidden="true" style = "margin-right:-200px;"></span>
                    <span class="sr-only">Previous</span>
                  </a>
                  <a class="carousel-control-next" href="#slides" role="button" data-slide="next">
                    <span class="carousel-control-next-icon" aria-hidden="true" style = "margin-left: -200px;"></span>
                    <span class="sr-only">Next</span>
                  </a>
                </div>
            </div>

              <div class = "h-40 center-me">
                <div class = "my-auto">
                    <form classs = "form-signin" action="includes/login-helper.php" method = "post" style="background: skyblue;">
                         <img class = "logo" src="images/Logo-1.jpg" alt="Logo" width="100" height="100">
                            <h1 class="h3 mb-3 font-weight-normal">Please sign in</h1>
                                <label for="inputEmail" class="sr-only">Username or Email Address</label>
                                <input type="text" name = "uname" id="inputEmail" class="form-control" placeholder="Username/Email" required autofocus>
                                <label for="inputPassword" class="sr-only">Password</label>
                                <input type="password" name = "pwd" id="inputPassword" class="form-control" placeholder="Password" required>
                            <div class="checkbox mb-3" style = "text-align: left;">
                                <label>
                                <input type="checkbox" value="remember-me"> Remember me
                                </label>
                             </div>
                    <button class="btn btn-lg btn-primary btn-block" name = "login-submit" type="submit">Sign in</button>
                    <p class="mt-5 mb-3 text-muted">&copy; 2020-2021</p>
                </form>

                </div>
            </div>
        </div>         
</main>