<?php require_once 'app/views/templates/headerPublic.php'?>
<main role="main" class="container">
    <div class="page-header" id="banner">
        <div class="row">
            <div class="col-lg-12">
                <h1>You are not logged in</h1>
            </div>
        </div>
    </div>

<div class="row">
    <div class="col-sm-auto">
		<?php
		session_start();
		if (isset($_SESSION['lockout_message'])) {
				echo '<div class="alert alert-danger" role="alert">' . $_SESSION['lockout_message'] . '</div>';
				unset($_SESSION['lockout_message']); // Clear the message after displaying it
		}
		?>
	
		<form action="/login/verify" method="post" >
		<fieldset>
			<div class="form-group">
				<label for="username">Username</label>
				<input required type="text" class="form-control" name="username">
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input required type="password" class="form-control" name="password">
			</div>
            <br>
		    <button type="submit" class="btn btn-primary">Login</button>
			<a href="app/views/signup/index.php" class="btn btn-primary"> Sign Up </a>
		</fieldset>
		</form> 
	</div>
</div>
<?php require_once 'app/views/templates/footer.php' ?>
