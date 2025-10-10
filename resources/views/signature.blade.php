<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Document</title>
    @vite(['resources/css/app.css', 'resources/js/main.js'])
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
</head>
<body>
    <form method="POST" action="{{ route("signatures.store") }}">
        @csrf
            <div class="mb-3 text-start">
              <label class="form-label">engine</label>
              <input name="engine" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">attackName</label>
              <input name="attackName" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">ruleText</label>
              <input name="ruleText" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">protocol</label>
              <input protocol type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">srcIp</label>
              <input name="srcIp" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">srcPort</label>
              <input name="srcPort" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">direction</label>
              <input name="direction" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">destIp</label>
              <input name="destIp" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">destPort</label>
              <input name="destPort" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">flow</label>
              <input name="flow" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">http</label>
              <input name="http" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">tls</label>
              <input name="tls" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">contentPattern</label>
              <input name="contentPattern" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">sid</label>
              <input  name="sid" type="text" class="form-control" placeholder="Enter your name">
            </div>

               <div class="mb-3 text-start">
              <label class="form-label">rev</label>
              <input name="rev" type="text" class="form-control" placeholder="Enter your name">
            </div>
            <button type="submit" class="btn btn-primary">Save</button>
            </form>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-FKyoEForCGlyvwx9Hj09JcYn3nv7wiPVlz7YYwJrWVcXK/BmnVDxM+D2scQbITxI" crossorigin="anonymous"></script>
</body>
</html>