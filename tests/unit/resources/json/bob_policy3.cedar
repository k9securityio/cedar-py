permit (
  principal,
  action == Action::"edit",
  resource
)
when { (resource["account"]) == principal };

permit (
  principal == User::"bob",
  action == Action::"view",
  resource
);

permit (
  principal,
  action == Action::"delete",
  resource
)
when
{
  (((context["authenticated"]) == true) && (resource has "account")) &&
  (principal == ((resource["account"])["owner"]))
};
