packet_use!();

packet!(Disconnect {
  reason: u32,
  message: String,
  language: String
});
