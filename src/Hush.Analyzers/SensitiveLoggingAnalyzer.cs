using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Hush.Analyzers;

/// <summary>
/// Reports HUSH001 when a value whose type, member or parameter is marked <c>[Sensitive]</c> is passed
/// to a logging call: <c>ILogger.Log</c>, the <c>LoggerExtensions.Log*</c> helpers, or a
/// <c>[LoggerMessage]</c> source-generated method. Interpolated strings and <c>params</c> arrays are
/// inspected element by element, because that is how secrets usually sneak into log lines.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class SensitiveLoggingAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "HUSH001";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Sensitive value passed to a logging call",
        messageFormat: "'{0}' is marked [Sensitive] and must never reach a logging call",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "Secrets and key material must never be written to logs. Log a name or a redacted form instead.");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
    }

    private static void AnalyzeInvocation(OperationAnalysisContext context)
    {
        var invocation = (IInvocationOperation)context.Operation;
        if (!IsLoggingMethod(invocation.TargetMethod))
        {
            return;
        }

        foreach (var argument in invocation.Arguments)
        {
            Inspect(context, argument.Value);
        }
    }

    private static void Inspect(OperationAnalysisContext context, IOperation? operation)
    {
        if (operation is null)
        {
            return;
        }

        operation = Unwrap(operation);

        switch (operation)
        {
            case IArrayCreationOperation { Initializer: { } initializer }:
                foreach (var element in initializer.ElementValues)
                {
                    Inspect(context, element);
                }

                return;
            case IInterpolatedStringOperation interpolated:
                foreach (var part in interpolated.Parts)
                {
                    if (part is IInterpolationOperation hole)
                    {
                        Inspect(context, hole.Expression);
                    }
                }

                return;
            case IBinaryOperation binary:
                Inspect(context, binary.LeftOperand);
                Inspect(context, binary.RightOperand);
                return;
        }

        var name = SensitiveName(operation);
        if (name is not null)
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, operation.Syntax.GetLocation(), name));
        }
    }

    private static IOperation Unwrap(IOperation operation)
    {
        while (operation is IConversionOperation conversion)
        {
            operation = conversion.Operand;
        }

        return operation;
    }

    private static string? SensitiveName(IOperation operation)
    {
        ISymbol? member = operation switch
        {
            IFieldReferenceOperation f => f.Field,
            IPropertyReferenceOperation p => p.Property,
            IParameterReferenceOperation p => p.Parameter,
            ILocalReferenceOperation l => l.Local,
            _ => null,
        };

        if (member is not null && HasSensitiveAttribute(member))
        {
            return member.Name;
        }

        // Members of a sensitive type (for example secret.Value) are sensitive too.
        if (operation is IMemberReferenceOperation { Instance: { } instance } && IsSensitiveType(instance.Type))
        {
            return instance.Type!.Name;
        }

        if (operation is IInvocationOperation { Instance: { } receiver } && IsSensitiveType(receiver.Type))
        {
            return receiver.Type!.Name;
        }

        return IsSensitiveType(operation.Type) ? operation.Type!.Name : null;
    }

    private static bool IsSensitiveType(ITypeSymbol? type)
    {
        for (var current = type; current is not null; current = current.BaseType)
        {
            if (HasSensitiveAttribute(current))
            {
                return true;
            }
        }

        if (type is IArrayTypeSymbol array)
        {
            return IsSensitiveType(array.ElementType);
        }

        if (type is INamedTypeSymbol { IsGenericType: true } generic)
        {
            foreach (var argument in generic.TypeArguments)
            {
                if (IsSensitiveType(argument))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool HasSensitiveAttribute(ISymbol symbol)
    {
        foreach (var attribute in symbol.GetAttributes())
        {
            if (attribute.AttributeClass?.Name == "SensitiveAttribute")
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsLoggingMethod(IMethodSymbol method)
    {
        var containing = method.ContainingType?.ToDisplayString();
        if (containing is "Microsoft.Extensions.Logging.LoggerExtensions" or "Microsoft.Extensions.Logging.ILogger")
        {
            return true;
        }

        if (method.ContainingType is { } type && type.AllInterfaces.Any(i => i.ToDisplayString() == "Microsoft.Extensions.Logging.ILogger")
            && method.Name == "Log")
        {
            return true;
        }

        var definition = method.PartialDefinitionPart ?? method;
        foreach (var attribute in definition.GetAttributes())
        {
            if (attribute.AttributeClass?.ToDisplayString() == "Microsoft.Extensions.Logging.LoggerMessageAttribute")
            {
                return true;
            }
        }

        return false;
    }
}
