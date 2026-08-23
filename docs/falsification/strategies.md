# Strategies

A strategy describes *how* to attack. A target describes *what* is attacked. They
compose, and the applicability matrix in `targets.py` decides which pairs are real.

| Strategy | Question it asks | Ships |
| --- | --- | --- |
| `mutation` | Can the tests detect realistic faults in this patch? | yes |
| `property` | Does a declared invariant hold across generated inputs? | yes |
| `adversarial` | Can an agent whose goal is failure find one? | yes |
| `differential` | Does the new implementation still agree with the old? | yes |
| `metamorphic` | Do the declared relations between executions hold? | yes |

## The interface

```python
class FalsificationStrategy(ABC):
    name: StrategyName

    def available(self, ctx) -> Availability: ...
    async def attack(self, ctx) -> StrategyReport: ...
```

Two rules the engine cannot enforce from outside:

* **Never raise for a failed attack.** Found nothing is `SURVIVED`. Broke is `ERROR`.
* **Never report `SURVIVED` for work you did not do.** A missing tool, an
  unsupported target or an exhausted budget is `UNAVAILABLE` or `INCOMPLETE`.

## Extension points

Adding a strategy means implementing the interface, registering it in
`StrategyRegistry.default()`, and adding it to the applicability matrix. The engine,
the DSL and the report format do not change.

Not implemented, and deliberately so: fuzzing, fault injection, chaos testing,
concurrency and race detection, browser adversarial testing, API contract attacks,
security fuzzing, SQL injection testing, authorisation boundary testing. Six targets
are registered for them already and report 0% coverage until they exist - a visible
gap is worth more than a silent one.

## Order

Default order is `mutation, property, differential, metamorphic, adversarial`:
cheapest and most deterministic first. Override per step with `order:`.
