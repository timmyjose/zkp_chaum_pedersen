//pub fn amain() -> Result<(), Box<dyn std::error::Error>> {
//    let mut auth_client = AuthClient::connect("http://zkp_server:9999").await?;
//
//    let request = tonic::Request::new(RegisterRequest {
//        user: "dummy user".into(),
//        y1: 54321,
//        y2: 54321,
//    });
//
//    let response = auth_client.register(request).await?;
//    println!("{response:?}");
//
//    Ok(())
//}
